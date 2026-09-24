# Close or falsify the CFW26 nonzero-coefficient theorem delta

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to
date as work proceeds. It is maintained in accordance with
`.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs to know whether it may safely instantiate a repaired version of
CFW26 Construction 11.4 with mask coefficient one and the scalar-multiplied
identity form. This artifact makes that decision reproducible from pinned
primary sources and executable finite-field checks. A reader can run one
dependency-free checker and see which local algebraic and formal nonadaptive
HVZK lemmas close, which published claims are falsified, and why theorem
inheritance and every production-facing authority remain disabled.

## Progress

- [x] (2026-08-22) Pin and read CFW26 Definitions 3.1--3.16, 4.1--4.7,
  5.1--5.8, Construction 6.3, Lemmas 6.4--6.5, and all of Section 11.
- [x] (2026-08-22) Pin and read the ACFY25 Appendix A construction and full
  RBR proof cited by CFW26 Section 11.
- [x] (2026-08-22) State the typed coefficient-`c` construction and prove its
  local completeness, value-distribution, and odd-characteristic outer-map
  lemmas.
- [x] (2026-08-22) Exhibit the printed endpoint-state and main-form defects,
  the dimension-dependent initial-RBR counterexample, and a fixed-set versus
  adaptive-query separation.
- [x] (2026-08-22) Implement and pass 19 initial dependency-free unit tests.
- [x] (2026-08-22) Finish the complete premise ledger, deterministic retained
  report, and fail-closed checker; verify every pre-manifest check passes.
- [x] (2026-08-22) Freeze the artifact manifest and complete the final
  independent rerun: 22 tests pass, the checker passes, and `git diff
  --check` is clean.

## Surprises & Discoveries

- Observation: The coefficient inconsistency is not the only completeness
  problem. Step 1's second state selects the coefficient of `X`, while the
  sampler constrains evaluation at one.
  Evidence: `X^2-X` evaluates to zero at both endpoints but its coefficient of
  `X` is nonzero.
- Observation: Theorem 11.3's first RBR coordinate substitutes outer-mask
  message length for the dimension of the initial residual polynomial.
  Evidence: over `F_101`, `d=10`, `L_in=4`, and `L_out=8`, the sparse invalid
  residual `product_i r_i` survives the initial challenge with probability
  about `0.10368`, exceeding the printed `9/101` bound.
- Observation: The proof sketch's word "adaptive" exceeds its premises.
  Evidence: Definition 4.7 is explicitly nonadaptive and Definition 3.16 only
  simulates a fixed query set; the retained pointer encoding separates the two
  notions with two queries.
- Observation: The factor two in the value claim and the powers of two in the
  outer affine-map proof have different origins. Replacing the former by any
  nonzero `c` does not remove the odd-characteristic premise needed by the
  latter.

## Decision Log

- Decision: Treat `c=1` plus `times(identity)` as an independent Hegemon
  restatement, not as an author-selected erratum.
  Rationale: It makes the local joint relation coherent, but no source erratum
  selects it and other literal defects still require repair.
  Date/Author: 2026-08-22 / Codex.
- Decision: Replace the endpoint state by `pow(1)` and define a row-MLE
  succinct form whose state is `(M,alpha)`.
  Rationale: These are the smallest typed changes that match the conditions
  the honest prover actually samples and the witness vector dimension.
  Date/Author: 2026-08-22 / Codex.
- Decision: Prove only the formal nonadaptive whole-view HVZK statement,
  conditional on Definition 3.16 encodings.
  Rationale: The published theorem's distinguisher class is nonadaptive; a
  fixed-set premise cannot support the proof sketch's adaptive wording.
  Date/Author: 2026-08-22 / Codex.
- Decision: Leave full corrected RBR open even after falsifying its first
  printed coordinate.
  Rationale: Section 11 supplies only a sketch and this bounded artifact does
  not construct every list-candidate knowledge-state and erasure-extraction
  transition.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The completed mathematical delta closes a typed `c!=0` construction's perfect
completeness and its formal nonadaptive HVZK argument, conditional on the
paper's encoding-ZK premises. It independently falsifies literal printed
completeness and the stated initial RBR budget, and separates fixed-set from
adaptive-query privacy. The ledger, report, manifest, and checker are complete;
22 unit tests and the independent checker pass. Nothing in this directory
authorizes adaptive complete ZK, Fiat--Shamir/QROM, PQ128 composition, theorem
inheritance, or production use.

## Context and Orientation

`THEOREM_DELTA.md` is the human-readable proof attempt.
`SOURCE_DEPENDENCY_MAP.json` pins every primary-source dependency and retained
page render. `cfw26_parametric_repair.py` implements only small prime-field
algebra, matrix ranks, and counterexamples, while
`test_cfw26_parametric_repair.py` exercises those checks. The remaining files
will be a theorem-premise ledger, deterministic JSON report, checker, and
hash manifest. No Hegemon runtime code or shared design document is in scope.

Round-by-round knowledge soundness, abbreviated RBR, is a security definition
requiring an extractor and a state predicate after every verifier challenge.
Honest-verifier zero knowledge, abbreviated HVZK, requires a simulator for the
verifier's whole view. A fixed-set simulator receives all query locations
before producing answers; an adaptive simulator must answer a query before it
learns the next location.

## Plan of Work

First, finish the executable model so its adaptive separation satisfies the
full fixed-set premise for every message, and strengthen the invalid-R1CS case
to record a complete accepting downstream path. Next, make the prose
self-contained by spelling out the repaired source and target relations and
every relevant occurrence of two. Then write a machine-readable ledger whose
individual results and global admission flags mirror the prose. Retain the
deterministic report, add a standard-library-only checker that re-executes all
invariants and pins the primary-source/page hashes, and finally generate a
manifest after every other artifact is stable.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon` and run:

    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
      -s .agent/hardening/cfw26-parametric-repair-proof -p 'test_*.py' -v

Then run:

    PYTHONDONTWRITEBYTECODE=1 python3 -B \
      .agent/hardening/cfw26-parametric-repair-proof/check_proof.py

Finally run:

    git diff --check -- .agent/hardening/cfw26-parametric-repair-proof

The checker must print a single `PASS cfw26-parametric-repair-proof` line that
also reports `theorem_inherited=false`, `complete_zk=false`, `qrom=false`, and
`production=false`.

## Validation and Acceptance

Acceptance requires every unit test and the independent checker to pass from a
cold Python invocation with bytecode writes disabled. Mutating `c` to zero,
restoring the printed endpoint state, treating the main form as literal
identity, restoring the printed first RBR bound, promoting adaptive ZK, or
changing any retained source page must make at least one check fail. The
artifact is accepted only with every global authority flag false except the
explicitly bounded local/conditional lemmas.

## Idempotence and Recovery

All commands are read-only after the retained report and manifest exist. The
experiments use exhaustive enumeration or fixed parameters and have no network
or external package dependency. If a legitimate edit changes a hash, rerun all
tests first and regenerate the manifest last; never weaken a checker to accept
an unexplained drift.

## Artifacts and Notes

The expected decisive numerical evidence is:

    F_101 sparse-invalid acceptance = 0.1036762825...
    printed first-coordinate bound  = 9/101 = 0.0891089109...
    fixed two-query distance        = 2/11
    adaptive two-query distance     = 1
    ell=2^25 encoding hybrid terms  = 105
    ell=2^25 printed RBR coordinates = 29

## Interfaces and Dependencies

The executable surface is `build_report() -> dict`, `self_check(report)`, and
the CLI in `cfw26_parametric_repair.py`. The checker imports that sibling
module and otherwise uses only Python's standard library. It may verify local
PDFs in `/private/tmp` when present, but the retained rendered pages make the
artifact auditable if those temporary source files are absent.

Revision note (2026-08-22): Created after the full dependency pass and initial
19-test executable audit so the remaining packaging and verification work is
restartable without conversation history.

Revision note (2026-08-22): Expanded the executable audit to 22 tests, added
the full target-relation restatement and theorem ledger, and verified that the
checker reaches only the deliberately absent manifest gate.

Revision note (2026-08-22): Froze the manifest and completed the independent
22-test, checker, and whitespace-validation rerun.
