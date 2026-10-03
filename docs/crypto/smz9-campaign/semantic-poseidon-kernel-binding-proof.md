# Bind the actual hash DAG to the pinned Poseidon2 permutation

This living ExecPlan follows `.agent/PLANS.md`. The coordinator owns the parent
complete-security plan. This lane owns this document and the additive module
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticPoseidonKernelBinding.lean`.

## Purpose / Big Picture

Replace the remaining gap between an arbitrary accepted source-DAG trace and
the exact width-16 Poseidon2 permutation with checked local gate correspondence
and round composition. Source replay alone is not primitive equality. Primitive
equality alone does not prove sponge framing or the typed cryptographic families.

## Progress

- [x] (2026-09-07 18:07 UTC) Independently checked the entire instance schedule
  against the pinned binary in an untrusted host parser: 5,630 distinct queries
  equal every non-root node in expression interval `[2036,7998)`.
- [x] Define exact source-index maps and sorted gate-query certificates.
- [x] (2026-09-07 18:57 UTC) Strict-check the full bounded certificate adapter.
- [x] Derive `External72`, `Sbox5`, and `Internal47` from actual source equations.
- [x] Compose the exact 4/22/4 rounds and bind all sixteen final lanes.
- [x] Apply that theorem to every accepted packed call without an honest-witness,
  desired-output, successful-decoder, or semantic-receipt premise.
- [ ] Strict-check, inspect axioms, and obtain coordinator review.

## Surprises & Discoveries

The two groups share all 150 round constants and sixteen internal diagonals.
They do not share the same numeric gate spacing. In particular, group zero's
first internal layer interleaves freshly allocated diagonal constants with its
products; later layers use already allocated constants. Source operand IDs are
sorted for commutative additions and multiplications. The certificate preserves
that exact ordering, and field arithmetic removes only its irrelevant orientation.

Each S-box has an earlier pre-S-box constrained row and a subtraction recovering
the previous state. The later power block adds the same constant back. Full
round correspondence therefore needs both the accepted recurrence and the
separately checked pre-state addition/subtraction nodes, not only the five power
gates. All 300 such transition maps were included in the host check.

## Decision Log

Use `checkHashQueries` to scan the original expression list in increasing node
order. Generated queries describe arithmetic templates, not copied final outputs.
Partition each of the two 2,732-query groups into 43 blocks of at most 64 queries,
and the shared 166 constant queries into three such blocks. Sort and check each
block, then prove that every original query belongs to a checked block.
The finite certificates use ordinary kernel reduction, never native proof
evaluation, added axioms, or opaque assumed source fixtures.

The first strict run localized a library visibility issue: the standard
`List.mergeSort` definition does not reduce under kernel `decide` through this
legacy import chain, even on a three-element example. A structurally recursive,
fuel-bounded local merge sort replaces that dependency; membership equivalence
is proved by induction for every fuel value. Whole-group reduction reached the
approved memory guard, so the certificates are partitioned into bounded blocks.
This changes neither query coverage nor the actual expression-list checker.
The bounded full-module check passed with no warnings or errors under the same
3,072 MiB Lean guard. All local first-run arithmetic and rewriting errors have
been repaired.

## Context and Orientation

The dependency chain is the frozen source interval/root certificates, semantic
hash recurrences, and the separately owned generic Poseidon2 arithmetic template
module. There are eighteen external linear layers, 300 S-boxes, and 44 internal
linear layers across the two 64-lane groups. The existing recurrence binds 332
constrained rows, including the final sixteen rows per group.

## Plan of Work

First certify exact indexed gates and pinned constants. Derive arithmetic gate
structures for arbitrary source interpretations. Use accepted hash recurrences
to cancel the pre-S-box constants, then connect each layer's output-node mapping
to the next layer's input-node mapping. Compose the full schedule with the
generic template module's `StateMatches` and kernel refinement theorems.

## Concrete Steps

All edits use `apply_patch`. Reuse Lean 4.32.2 and cached dependencies; no Rust
build, shared-cache write, git operation, or node action is in scope. Once the
coordinator has cached every frozen dependency and assigned a check slot, run
from `formal/crypto`:

    lake env lean -j1 --memory=3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticPoseidonKernelBinding.lean

If the memory guard is reached, report it and localize or partition the check;
do not run an unbounded retry. Keep this additive lane below 20 MiB of source
and scratch, with at most one own Lean process and centralized slot scheduling.

## Validation and Acceptance

The actual node certificate, local field arithmetic, full schedule, and accepted
packed-call specialization are distinct proof obligations. Record strict exit
status and `#print axioms` for public endpoints. Only `propext`, `Classical.choice`,
and `Quot.sound` are allowed as applicable. Preserve the still-separate sponge,
typed cryptographic-link, privacy, and production-authorization boundaries.

## Idempotence and Recovery

Only the two owned additive files change. Dependencies are frozen by their owners
and cached by the coordinator. Do not modify their statements to make this
adapter easier to prove. No runtime relation, wire format, or retained artifact
is changed.

## Outcomes & Retrospective

The complete source passed strict Lean checking on 2026-09-07 by 18:57 UTC.
The host map established exact implementation targets; the kernel-checked
certificate and arithmetic proofs now supply the corresponding proof credit.
At 18:20 UTC the complete source attempt includes all local gate derivations,
finite round-transition schedules, generic scheduled-round induction, and
`accepted_hash_call_final_refines_kernel` for all 128 calls and sixteen lanes.
It also contains the canonical-representative strengthening
`accepted_hash_call_final_eq_kernel`, whose conclusion is exact natural-word
equality and whose only semantic premise is the same packed acceptance.
Both endpoints passed the complete strict check, with warnings as errors,
automatic implicit variables disabled, one Lean worker, and a 3,072 MiB memory
guard. The resulting isolated output and audit source occupy 2.6 MiB.
Exported-axiom inspection and coordinator readback are still pending.

## Interfaces and Dependencies

Consume `HashRecurrence` and `accepted_hash_recurrence` from the semantic source
module, and `External72`, `Sbox5`, `Internal47`, `StateMatches`, and the full
permutation refinement from the generic arithmetic module. The intended endpoint
is equality of every accepted final hash lane with the exact kernel permutation
of that call's actual initial state.
