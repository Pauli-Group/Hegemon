# Red-team the inactive HX512 full-relation compiler

This ExecPlan is a living document maintained under `.agent/PLANS.md`. It owns
only `.agent/hardening/hx512-full-relation-redteam/` and does not authorize
Cargo, rustc, Lake, proof generation, expanded-matrix generation, production
routing, or edits to the compiler owner's files.

## Purpose / Big Picture

Independently determine whether the HX512 source compiler defines an exact
transaction relation or only a row-count projection. A reviewer must be able
to run one dependency-free checker that recomputes geometry, exercises
counterfeit statement and witness mutations, compares the verifier context to
the frozen all-W64 kernel grammar, and demonstrates whether the odd-field
macros may be reinterpreted over characteristic two. Every proof, security,
refinement, release, and production authority remains false.

## Progress

- [x] (2026-08-22) Read repository instructions, the execution-plan rules,
  canonical README, transaction/hash/stablecoin portions of `DESIGN.md` and
  `METHODS.md`, and the living production ExecPlan.
- [x] (2026-08-22) Inspect the compiler, semantic suite, frozen odd-field macro
  library, Python manifest authority, and inactive Rust all-W64 kernel source.
- [x] (2026-08-22) Report the verifier-context and policy-version divergences,
  operand-free macro ledger, and incomplete reference evaluator to the compiler
  owner and lead.
- [ ] Implement the dependency-free audit and retained counterfeit corpus.
- [ ] Re-run against the compiler owner's frozen artifacts, record exact hashes,
  and hand off the final blocker list.

## Surprises & Discoveries

- Observation: the compiler's `Program` stores only aggregate primitive counts;
  invocations have no input/output variable identities or sparse coefficients.
  Evidence: `Program.invoke` records only macro, multiplicity, width, and prose
  note, while `primitive` increments counters.
- Observation: the Python compiler context is a snapshot digest plus height,
  but the frozen Rust all-W64 public authority is manifest root plus height.
  Evidence: `VerifierContext.encode` and
  `StablecoinManifestPublicAuthorityV2::encode_canonical` encode different first
  64-byte values.
- Observation: the odd-field row count cannot be reused as a binary/Aurora
  relation count. In characteristic two, the coefficient two vanishes from the
  full-adder equations and parity replaces one-hotness.
  Evidence: invalid carry and three-hot assignments satisfy the printed macro
  equations over GF(2).

## Decision Log

- Decision: distinguish exact arithmetic recounting from semantic compilation.
  Rationale: matching `m`, `n`, and nonzero totals cannot establish source-to-
  operand wiring or witness satisfaction.
  Date/Author: 2026-08-22 / Codex.
- Decision: retain executable counterexamples instead of relying on mutation
  labels.
  Rationale: the owner artifact's mutation corpus is descriptive until a test
  actually mutates bytes and evaluates the alleged full relation.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

Work is in progress. The audited compiler remains inactive and all security and
production authority is false.

## Context and Orientation

`.agent/hardening/hx512-full-relation-compile/compiler.py` imports a frozen
Goldilocks macro counter, the HX512 semantic suite, and the all-W64 authority
reference. `verify_reference` is a host-language predicate used by its sample
and tests. `Program` is called a macro compiler but does not retain an expanded
or compact operand graph. `protocol/kernel/src/stablecoin_manifest_authority_v2.rs`
is the inactive Rust codec and parent-state contract against which the Python
context must be checked.

## Plan of Work

Add `audit.py` that imports the current compiler without writing artifacts,
recomputes every group and primitive total from independent arithmetic, checks
all source/private section partitions, derives BLAKE call/block counts from the
semantic schedule, and inspects canonical endianness and context contracts.
Exercise the compiler's own sample through byte mutations across core public and
private regions. Record mutations accepted by `verify_reference` even though
their named transaction semantics change. Evaluate the printed full-adder and
one-hot equations over GF(2) and retain concrete satisfying counterexamples.

Generate `audit_report.json` and `counterfeit_corpus.json` canonically. The
report must never call an operand-free count ledger an exact compiled relation
and must keep proof bytes null plus every authority flag false.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-full-relation-redteam/audit.py --write
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-full-relation-redteam/audit.py --check
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-full-relation-redteam/test_audit.py
    git diff --check -- .agent/hardening/hx512-full-relation-redteam

## Validation and Acceptance

The checker must reproduce retained JSON byte-for-byte, independently sum every
group and primitive contribution, cover the full statement/context/private
partitions, retain actual accepted counterfeits for each unchecked core family,
show the root-versus-snapshot context difference if still present, and show
invalid characteristic-two carry and one-hot assignments. It passes as an
audit when findings are exactly and fail-closedly recorded; it does not pass the
production objective.

## Idempotence and Recovery

Generation is deterministic and overwrites only this directory's two generated
JSON files. It imports owner sources read-only and never runs a compiler write
mode. If those sources change during the audit, rerun after they freeze and
update the source-bound expected findings.

## Artifacts and Notes

The final report will include source SHA-512 values, exact geometry arithmetic,
counterfeit offsets, and characteristic-two assignments.

## Interfaces and Dependencies

Use only the Python standard library. `audit.py` exposes `build_report()`,
`build_counterfeit_corpus()`, `write_outputs()`, and `check_outputs()`. Tests
must import the module by path and must not modify owner artifacts.

Revision note (2026-08-22): created the isolated red-team plan after the first
context, parser-language, reference-evaluator, and field-characteristic defects
were reproduced.
