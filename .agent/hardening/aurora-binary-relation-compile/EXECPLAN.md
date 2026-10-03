# Close out the Aurora binary-relation lane without relation authority

This ExecPlan is a living document maintained according to `.agent/PLANS.md`.

## Purpose / Big Picture

The Aurora screen attempted to transport the prospective HX512B01 transaction relation into a
binary-field R1CS. The attempt found characteristic-two breakage in the odd-field full-adder and
selector equations, then found that the shared full-relation compiler was count-only and its
policy-master schedule had not frozen. This closeout retains the useful source-macro projection and
the exact negative verdict without presenting either as a matrix, proof, security result, or
architecture winner.

## Progress

- [x] (2026-08-22) Read repository instructions, design/methods boundaries, the active production
  plan, and Aurora Definition 7.1/Theorem 9.2.
- [x] (2026-08-22) Identified characteristic-two invalidity in odd-field `2*c` carry equations and
  parity-only selector cardinality.
- [x] (2026-08-22) Derived the last reproducible pre-correction source-macro projection and libiop
  public-padding remap.
- [x] (2026-08-22) Confirmed no concrete characteristic-two `A/B/C` coordinates or executable typed
  lowering were retained.
- [x] (2026-08-22) Found the 1,024-row policy-master drift between the retained count projection and
  the later semantic source.
- [x] (2026-08-22) Replaced the prospective compiler artifact with a negative manifest,
  certificate, mutation corpus, and dependency-free fail-closed checker.
- [x] (2026-08-22) Kept every backend, proof, security, refinement, release, and production
  authority false and corrected final geometry null.

## Surprises & Discoveries

- The odd-field equations `(x+y+c-s-2*c_next)=0` lose the carry in characteristic two. A generic
  binary-field mapping needs separate parity and majority/carry rows unless a concrete field and a
  coefficient outside `F2` are selected and proved safe.
- Five-way sum-equals-one and conditional four-way cardinality reduce to parity in characteristic
  two. Pairwise-zero constraints or another proved exact one-hot construction are required.
- The retained macro projection used 1,536 policy-master rows and total source `m=29,509,133`; the
  later semantic source requires 2,560 policy-master rows and `m=29,510,157`. Therefore even the
  source-macro geometry did not reach a final frozen state.
- The two policy masters are 64 bytes each at private offsets 6,088 and 6,152. Their relation
  constraints cannot establish wallet entropy or lifecycle.

## Decision Log

- Decision: Freeze the lane as `NO_EXECUTABLE_CHARACTERISTIC_TWO_SPARSE_R1CS`.
  Rationale: a count ledger plus primitive templates is not a canonical sparse relation.
  Date/Author: 2026-08-22 / Aurora relation compiler worker.
- Decision: Retain the old tuple only under `last_reproducible_pre_correction_projection`.
  Rationale: it is useful provenance but is invalid as final geometry after the policy-master
  repair.
  Date/Author: 2026-08-22 / Aurora relation compiler worker.
- Decision: Keep the Aurora padding values as a projection only.
  Rationale: no field, codeword domain, shifted-domain disjointness proof, or backend exists.
  Date/Author: 2026-08-22 / Aurora relation compiler worker.
- Decision: Bind the V2 context grammar to `manifest_root64 || parent_height:u64le` and separately
  record native parent authentication as false.
  Rationale: a snapshot digest cannot substitute for the canonical verifier context.
  Date/Author: 2026-08-22 / Aurora relation compiler worker.

## Outcomes & Retrospective

The retained result is a verified negative artifact, not a relation compiler. It preserves the
pre-correction `37,364,095 / 21,531,353 / 9,704 / 156,526,483` source-macro projection and its
power-of-two padding, while setting corrected `m/n/nnz`, proof bytes, and security bits to null.
Every authority flag remains false. Any future binary-field backend must start from a newly frozen
executable typed relation and retain or reproducibly generate canonical sparse coordinates.

## Validation and Acceptance

The checker must byte-semantically match the three retained JSON objects, reject any positive
authority or fabricated corrected geometry, enforce the exact V2 context grammar, retain the
policy-master 1,024-row gap, pin the inactive V2 kernel source, and leave proof bytes/security null.
The tests exercise positive-authority, fabricated-geometry, context, identity, policy-master, and
padding mutations. No command compiles a relation or builds a proof.

Run from `/Users/pldd/Projects/Reflexivity/Hegemon`:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-binary-relation-compile/compiler.py --check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-binary-relation-compile/compiler.py --summary
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-binary-relation-compile/test_compiler.py
    git diff --check -- .agent/hardening/aurora-binary-relation-compile

## Idempotence and Recovery

The checker is read-only and has no artifact-write mode. It touches no shared lane, production
registry, or route. Source drift fails closed; do not reset, clean, or delete shared worktree state.
