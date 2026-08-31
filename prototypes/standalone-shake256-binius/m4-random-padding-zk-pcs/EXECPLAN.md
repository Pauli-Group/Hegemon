# Audit random high-coefficient padding for the compact PCS

This ExecPlan is a living document maintained according to `.agent/PLANS.md`.
It is intentionally scoped to an isolated source-only prototype; shared design,
method, consensus, ledger, and frontier files are out of scope.

## Purpose / Big Picture

The maximum SHAKE256 M4 proof needs a hiding polynomial commitment that is much
smaller than the rejected two-share construction. This experiment determines
whether fresh randomness placed in unused high coefficients can hide the union
of codeword openings and algebraic linear messages without a second
commitment. A maintainer can run one lightweight Python suite to see the exact
rank theorem, adversarial failures, and byte/resource screen. The experiment
must fail closed until the real M4/FRI matrix and complete security proof exist.

## Progress

- [x] (2026-08-21 19:39Z) Read the project plan, design, methods, frozen full-M4 source inventory, and prior PCS screens.
- [x] (2026-08-21 19:48Z) Implemented exact generic GF(2^m) arithmetic, B128 Gaussian rank, fixed-matrix independence/full-uniform audits, and exhaustive small-field distributions.
- [x] (2026-08-21 19:55Z) Added the nonzero affine RS domain, Vandermonde tail certificate, explicit zero-point leakage negative, and combined query plus terminal/fold E256 rank matrix.
- [x] (2026-08-21 20:01Z) Added salted four-symbol leaf/node seams, two domain-separated E256 transcript branches over one root, and exact rate-1/16 and rate-1/32 wire/resource screens.
- [x] (2026-08-21 20:05Z) Added exhaustive fixed-matrix rank/distribution equivalence, rank-deficiency, adaptive-selection, random-tail reuse, branch separation, wire, capacity, and fail-closed gate regressions.
- [x] (2026-08-21 20:18Z) Split double-full-budget from conditional 132-bit-per-branch profiles, separately charged the 1,920-byte local characteristic-two floor plus 128-byte fused ring switch, and pinned the source-static 23,594..32,668 active-symbol interval; 23 tests pass.
- [x] (2026-08-21 20:42Z) Corrected the authoritative commitment and Fiat--Shamir profile to 64-byte SHAKE256-512, demoted every 56-byte SHAKE256-448 row to a negative control, and added separate 32-byte-unproved and 148-byte-direct-BCS salt profiles; 26 tests pass.
- [ ] Replace the active-symbol assumption and placeholder terminal/FRI rows with a compiled source-bound maximum-M4 matrix; blocked by the disk gate and missing PCS/PIOP implementation.
- [ ] Prove adaptive BCS zero knowledge, RS/FRI extraction, shared-commitment E256 parallel repetition, and composed QROM/PQ128 security; this prototype supplies none of those theorems.

## Surprises & Discoveries

- Observation: a monomial high-coefficient pad gives no hiding at evaluation point zero.
  Evidence: the exact row at zero is `[1,0,...,0]`, its padding rank is zero, and exhaustive GF(16) distributions differ for every constant coefficient.
- Observation: full rank for every realized adaptive row does not imply hiding when the row selection depends on the padding.
  Evidence: a one-row GF(2) selector whose chosen row is always nonzero returns the witness with probability `3/4`.
- Observation: strict SHAKE256-512 commitment width eliminates the full-budget rate-1/32 fit.
  Evidence: the strict full independent row is 128,512 bytes, 4,444 over cap; the conditional row is 69,632 bytes but its product theorem is false.
- Observation: the old compact numbers were non-strict SHAKE256-448 geometry.
  Evidence: 63,320 and 116,952 remain byte-exact only under explicit 56-byte negative-control profiles; widening costs 6,312 and 11,560 bytes respectively.
- Observation: a 148-byte salt is not automatically a strict-ZK fix.
  Evidence: it reaches the direct classical BCS n18 salt floor, but corresponds to lambda 592 while the strict digest is 512 bits, and the theorem is not QROM.
- Observation: the static geometry interval is too wide to authorize random-padding capacity.
  Evidence: active symbols are only narrowed to 23,594..32,668, leaving 100..9,174 random coefficients; the conditional rate-1/32 row needs at least 1,060 and is short by 960 at the upper endpoint.
- Observation: the current source cannot justify a concrete n15 tail length.
  Evidence: `REALIZATION_MAP.md` requires the implemented circuit to emit the active-row count; the source-only 26,000 value is explicitly an assumption.

## Decision Log

- Decision: use a nonzero additive affine coset rather than a zero-containing linear evaluation subspace.
  Rationale: consecutive high monomials cannot mask the constant evaluation at zero.
  Date/Author: 2026-08-21 / Codex.
- Decision: expand every E256 terminal/fold functional into two B128 rows and rank the complete union once.
  Rationale: checking point openings alone can miss a leaking algebraic message.
  Date/Author: 2026-08-21 / Codex.
- Decision: price both shared schedules and the worst union of two independent schedules.
  Rationale: shared queries are cheaper but domain-separated challenges alone do not justify a product soundness error.
  Date/Author: 2026-08-21 / Codex.
- Decision: retain the existing `5*q+2` E256 first-level charge and label it optimistic.
  Rationale: it permits comparison with the prior screen without pretending it is a complete FRI transcript.
  Date/Author: 2026-08-21 / Codex.
- Decision: add a separate conditional 132-bit query budget per independent E256 branch while retaining 264-bit-per-branch controls.
  Rationale: under a future parallel-RBR theorem, two 132-bit branch errors are the proper analogue of one 264-bit schedule; without that theorem, the smaller row has no security authority.
  Date/Author: 2026-08-21 / Codex.
- Decision: charge 1,920 local characteristic-two bytes and 128 fused-ring-switch bytes outside `5*q`.
  Rationale: neither term is part of the opening field-message floor, and omitting them would reward an incomplete transcript.
  Date/Author: 2026-08-21 / Codex.
- Decision: pin the source-static geometry counter but never treat its 26,000 sensitivity point as valid.
  Rationale: only compilation can select the actual active prefix inside the 23,594..32,668 source-static interval.
  Date/Author: 2026-08-21 / Codex.
- Decision: make 64-byte SHAKE256-512 roots, nodes, and Fiat--Shamir digests authoritative.
  Rationale: the strict Hegemon profile requires SHAKE256-512 proof commitments and transcript hashing; a 56-byte commitment is a specification mismatch.
  Date/Author: 2026-08-21 / Codex.
- Decision: retain SHAKE256-448 only through separately named negative-control functions and report rows.
  Rationale: preserving old arithmetic is useful for explaining the exact widening cost but cannot create strict evidence.
  Date/Author: 2026-08-21 / Codex.
- Decision: price both the 32-byte candidate salt and the direct-classical-BCS 148-byte n18 floor.
  Rationale: the compact salt is unproved, while the larger salt still lacks one common BCS lambda and a QROM simulator; neither may promote.
  Date/Author: 2026-08-21 / Codex.
- Decision: do not build or allocate the production oracle below 28 GiB free.
  Rationale: the model is algebraic and arithmetic; an allocation cannot close any missing theorem and would violate the disk gate.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The source-only construction survives one necessary screen. A conventional
rate-`1/32` RS oracle, independent worst-union query openings, four salted B128
symbols per strict 64-byte SHAKE256-512 leaf, two E256 branches, one root, the
local characteristic-two floor, and one fused ring switch total 128,512 raw
bytes when each branch carries a full 264-bit query term. This is 4,444 bytes
over the raw cap. At the non-authoritative
26,000-symbol sensitivity point, the 6,768-symbol tail has a 4,784-row capacity
margin against a conservative 1,984-row view.

The conditional 132-bit-per-branch strict version is 69,632 bytes and has a
5,708-row capacity margin at that same sensitivity point. It is the most
compact surviving strict geometry, not a security result: its required
half-budget parallel-RBR product theorem is explicitly false and its 32-byte
salt remains unproved.

Replacing that salt with the 148-byte direct-classical-BCS n18 floor raises the
conditional row to 77,288 bytes and stored tree to 72,351,680 bytes. It still
does not instantiate that classical theorem with the 512-bit digest and does
not supply a QROM simulator. The old 63,320/116,952 rows remain only as
non-strict SHAKE256-448 negative controls.

This is not a candidate or a proof-size point. The full-budget result is
conditional on a real compiled active prefix of at most 30,784 symbols, one
fixed full-rank union matrix, a relation that soundly excludes the random tail,
and security theorems not present here. The source-static active interval
extends to 32,668 and therefore does not close even capacity. The smaller
conditional row additionally assumes the missing parallel product theorem and
a valid salt/QROM compiler. The
adaptive counterexample shows why the exact rank result cannot itself establish
Fiat--Shamir zero knowledge.

## Context and Orientation

The prospective maximum relation lives in
`prototypes/standalone-shake256-binius/m4-full-production-prototype/`. Its
source fixes 83 Keccak-f permutations and 3,187,200 Boolean ANDs but has not
been compiled under the current disk gate. The prior strict screen in
`.agent/hardening/binius-pq128-proof-size/strict-mixed-pcs-screen/` historically
prices four-symbol SHAKE256-448 leaves and E256-by-two algebra. That digest
width is now a negative-control geometry here because it does not satisfy the
strict profile. This directory adds only the random high-coefficient hiding
hypothesis and its exact fixed-matrix audit.

A B128 symbol is an element of `GF(2^128)` in the pinned GHASH polynomial
basis. E256 is a quadratic extension represented by two B128 coordinates. A
Merkle multiproof sends queried leaves once plus the minimum sibling frontier
needed to reconstruct one root. A query schedule is adaptive here whenever it
depends on the random padding or on a root computed from that padding.

## Plan of Work

Keep `random_padding_pcs.py` dependency-free. It must expose generic binary
field arithmetic, exact matrix rank, the rank audit, exhaustive distribution
enumeration, RS evaluation rows, E256 coordinate expansion, the nonzero affine
domain, salted leaf/node hashing, branch challenge derivation, and wire
profiles. Strict roots, nodes, and Fiat--Shamir digests must be exactly 64-byte
SHAKE256-512 outputs. Any 56-byte profile must be named and reported only as a
non-strict negative control. Keep every production capability boolean false in
`report()`.

Keep `test_random_padding_pcs.py` adversarial. It must cover the positive
fixed-matrix theorem and the zero-domain, rank-deficiency, terminal-row,
adaptive-selection, and key-reuse failures. It must assert exact rate profiles
so a silent byte change fails loudly, including the 64-vs-56 widening deltas and
32-vs-148 salt charges.

When a compiled maximum-M4 backend becomes available above the disk gate, it
must export the exact active coefficient count and every B128-linear
observation row after both E256 branches are expanded. Feed that full matrix to
`audit_observation_matrix`; do not infer rank from a row count. Only after the
PIOP and BCS reductions prove that the schedule is covered may the corresponding
gate change.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon` and run:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs/random_padding_pcs.py \
      --check --report

The first line must be:

    RANDOM_PADDING_PCS_CHECK_PASS

Then run:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs/test_random_padding_pcs.py

The final lines must report 26 tests and `OK`. Check whitespace with:

    git diff --check -- \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs

## Validation and Acceptance

Acceptance for this milestone is limited to source-only evidence. The exact
B128 rank calculator must agree with the Vandermonde certificate on a real
B128 instance. Exhaustive GF(16) distributions must be fully uniform and equal
across witnesses for a full-rank union of an RS opening and an E256
terminal/fold functional. The zero point and a duplicated terminal row must
fail. The adaptive selector must remain biased and tail reuse must cancel.
Wire records must remain exact, and every production gate must remain false.
The strict rate-1/32 conditional row must be 69,632 bytes; the strict full
independent row must be 128,512 bytes; and the corresponding 56-byte controls
must be rejected as non-strict. Neither the 32-byte nor 148-byte salt profile
may become promotable.

No proof artifact, production frontier row, or security claim is an acceptance
criterion for this milestone.

## Idempotence and Recovery

The Python commands read source and print results only. They set
`PYTHONDONTWRITEBYTECODE=1`, allocate no production codeword, and write no cache.
If a test fails, edit only this isolated directory and rerun it. Do not clean a
shared Cargo target or delete any repository artifact. Cargo and production
proving remain forbidden below 28 GiB free.

## Artifacts and Notes

The frozen source inventory used by the screen is:

    main.rs SHA-256 d1ad66f1d5d3203bbc716b2c88157153eb42a06fde95a9df8eaad187e96a454c
    lib.rs  SHA-256 67e7f6ac6a15579043de5a9a0565b374667b094890bbf31053a818479697ed91

Those hashes bind static source, not a compiled active-symbol count. The
strict double-full-budget control row is:

    rate=1/32 schedules=independent-worst-union bits=264 per branch
    digest=SHAKE256-512 q=66 opened_leaves=132 frontier_nodes=1444
    raw_bytes=128512 raw_cap_overage=4444
    conservative_B128_views=1984 sensitivity_tail=6768

The conditional compact strict row is:

    rate=1/32 schedules=independent-worst-union bits=132 per branch
    digest=SHAKE256-512 q=33 opened_leaves=66 frontier_nodes=788
    raw_bytes=69632 candidate_salt_bytes=32 salt_pq128_proved=false
    conservative_B128_views=1060 half_budget_product_theorem=false

The theorem-scoped larger-salt row and non-strict controls are:

    strict conditional salt_bytes=148 raw_bytes=77288 promotable=false
    NONSTRICT SHAKE256-448 full=116952 conditional=63320

## Interfaces and Dependencies

`random_padding_pcs.py` uses only the Python standard library. The stable
interfaces are `BinaryField`, `matrix_rank`, `audit_observation_matrix`,
`exhaustive_distribution`, `polynomial_evaluation_row`,
`expand_e256_functional`, `observation_union_matrix`,
`vandermonde_tail_certificate`, `affine_domain_point`, `salted_leaf_hash`,
`merkle_node_hash`, `branch_transcript_digest`, `branch_challenge_e256`,
`salted_leaf_hash_nonstrict_shake448`,
`merkle_node_hash_nonstrict_shake448`, `WireProfile`, and `report`.

Revision note: corrected strict commitment/Fiat--Shamir width and added
theorem-scoped salt profiles on 2026-08-21. Production implementation and every
security theorem gate remain open.
