# Refine the actual SMZ9 ordered-root collector

This living ExecPlan follows `.agent/PLANS.md` and continues
`.agent/SMZ9_COMPLETE_SECURITY_EXECPLAN.md`. It owns only the wrapper in
`circuits/transaction/src/smallwood_poseidon2_v8_ir.rs`, its focused tests,
new isolated extraction/proof artifacts and directly related documentation.

## Purpose / Big Picture

The actual SMZ9 program evaluator must return exactly the requested node
values, in order and with duplicates, after evaluating every node. Invalid
roots must return the existing error, while any node-evaluation error must
take precedence even when roots are empty. Establishing this native step is
required to connect the existing source-level acceptance proofs to Rust.
This is not a cryptographic security endpoint or permission to enable production.

The unchanged-source Stage 7 extraction is preserved under
`.agent/artifacts/smallwood-poseidon2-v8/native-root-extraction-a22be43b2054922a`.
It exposes four unsupported standard-library operations: generic iterator
map, the Map iterator instance, Result collection and Option-copied. Rather
than adding new library assumptions, this plan changes the actual wrapper
to a checked explicit loop using already modeled operations. The equivalence
claim covers returned elements and errors, not vector capacity, allocator
behavior or out-of-memory failure. Those are already outside the native
proof runtime's vector model and are not silently promoted to proved facts.

## Progress

- [x] (2026-09-09) Extract and retain original wrapper bytes, declarations,
  input inventories, log and receipt; independently verify all 520 payloads.
- [x] (2026-09-09) Independently identify the four missing operation bindings
  and verify that checked lookup, Option-ok-or, propagation, explicit slice
  iteration, Vec-new and Vec-push have existing frozen models.
- [x] (2026-09-09) Replace only root collection in the actual Rust function and add a
  test-only original implementation with bounded differential controls.
- [x] (2026-09-09) Pass all six focused Rust tests, including the 510-case
  exact grid, and check that the source diff preserves the
  node evaluator, program construction/serialization and all dependencies.
- [x] (2026-09-09) Freeze new source SHA-256
  `a580c88243eb6551e60b28c07f57c7ab6b3d3c44f8c007361568d1726fa1bd47`
  and run offline tests/extraction with clean child exits. Preserve the failed
  broad Map-type inspection; separate independent read-only review verifies
  exact source bytes and absence of unsupported reachable operation calls.
- [x] (2026-09-09) Perform separately guarded strict Aeneas translation using
  the existing candidate. Preserve the Stage 9 invariant-check failure and
  both failed receipts without relabeling; no translation proof is credited.
- [ ] Correct and qualify the independently identified return-value
  region-erasure constructor mismatch in a new isolated translator candidate,
  preserving all invariants and existing frozen tools; then qualify strict
  translation of the actual wrapper.
- [ ] Audit generated declarations and prove ordered-root induction against
  the original source-shaped program semantics; include invalid-root,
  duplicate/order and empty-root boundaries. Do not assume native success.
- [ ] Retain and independently read back exact qualified artifacts; compose
  with the existing node proof only after an exact body/source comparison.
- [ ] Update main progress and implementation/refinement documentation.

## Surprises & Discoveries

The frozen runtime's Map structure is only a type, not its iterator
implementation. Iterator-collect is present but delegates to an absent
Result-FromIterator instance. The original wrapper also calls an unsupported
Option-copied operation. The new loop must dereference the checked `get`
result rather than keeping that operation. Explicit `.iter()` avoids
introducing a shared-Vec IntoIterator dependency.

The Stage 8 parser's blanket Map-type rejection is too broad: Charon retains
unused Map, FilterMap, MapWhile, FlatMap and MapWindows type metadata even
though no reachable wrapper/node signature or body references them and no
map, collect, copied or from_iter function declaration remains. The original
receipt stays failed. Independent exact-source and reachable-callee review
is recorded separately; strict translation is a separate acceptance step.

Stage 9 reaches the actual wrapper but fails the unchanged typing invariant
at `interp/Invariants.ml:422` immediately after the node-function call and
before `Try::branch`. The called function returns a symbolic
`Result<Vec<u64>, &'static str>`. Static source tracing finds that
`ValuesUtils.mk_tvalue_from_symbolic_value` uses Charon's region-variable-only
erasure, which preserves the static lifetime that `ty_is_ety` rejects.
Changing only that constructor would then conflict with the expected-type
calculation at `Invariants.ml:536`; both must use a consistent erasure
definition without dropping their checks. This is a concrete source-level
mismatch, not a printed identification of the exact failing context binding.

## Decision Log

Use `Vec::new()` and push each successfully checked value. Do not eagerly
allocate a root-sized vector before finding an invalid first root. Keep the
complete node-evaluation call before constructing the result. Preserve the
exact error literal and casts. No expression enum, arithmetic, compiler,
wire, proof profile, primitive, dependency, network or production-capability
change is included. No retained receipt is relabeled to the new source.

The user has requested implementation and completion of the full SMZ9 work.
This local refactor is an implementation step in that scope; it grants no
push, deployment or release authority. Existing unrelated AGENTS and skill
edits remain untouched. A tool denial must not be bypassed by a different
route; the previously denied K8 work is not part of this packet.

## Outcomes & Retrospective

The actual wrapper refactor passes six focused Rust tests, including the
exact 510-case differential grid. Independent source review finds no issue
and confirms that all pre-wrapper bytes are unchanged. Source and test
identity are newly frozen; old receipts remain historical. Both offline
compiler commands exit zero, but the Stage 8 receipt correctly remains failed
at its overly broad type-inventory assertion. Separate static review verifies
the LLBC source and reachable calls without rerunning or relabeling it.
The separately reviewed strict translation fails inside the translator's
typing invariant; no root-loop proof or full production build is claimed.
The 2,511-declaration source gate and 17-root native node loop qualification
remain preserved evidence for their exact sources.

## Context and Orientation

The wrapper starts at line 510 of
`circuits/transaction/src/smallwood_poseidon2_v8_ir.rs`. The original file's
SHA-256 is `608786dc9232c22612da6ce4e13bab4fdfe354be2065cdc08227a9ceff618454`.
Its only production caller is `evaluate_all_constraints` in
`circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs`, which maps the
same error into `TransactionCircuitError::ConstraintViolation`. The returned
vector is the nonlinear constraint values, not a new proof or wire encoding.

Existing tools are frozen under `/private/tmp/smz9-native-tools.lS4uVwgg`
and `/private/tmp/smz9-aeneas-stage1.IgNKumAA`. Charon 0.1.248 uses the already
installed nightly-2026-08-18 compiler. The retained two-line region-erasure
Aeneas candidate is
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage5-erasure-candidate/build/default/main.exe`,
SHA-256 `b2ea49f1ac27930e20dc19f430b7ca4f5284119fe322f4addeaac0e1c1e0de37`.
Lean 4.31.0 and its current frozen library roots are reused, not installed or
modified. Compiler and standard-library correspondence remain explicit
engineering assumptions; the resulting artifact is not hermetic.

## Plan of Work

First replace the iterator chain with a local output vector and explicit
slice iterator. For each root, checked lookup and the unchanged error
propagation precede push. Return the resulting vector after the loop.
Append a private test module retaining the exact old wrapper body as an
oracle; both versions call the same unchanged node evaluator.

Then check empty inputs, order, duplicates, invalid first/later roots,
u32-maximum roots, noncanonical constant preservation, and public/witness
node errors, including unreferenced failing nodes. The deterministic grid
must report and assert its finite case count. It is regression evidence,
not a universal equivalence theorem or resource-behavior proof.

After tests, create a new scratch extraction packet and bind its manifest
to the new source bytes. Reuse the reviewed one-shot process-group guard,
exact input inventories and network-denying scratch-only sandbox. Every
command is serial and resource-monitored. Translation failures are retained
without silently editing generated code or libraries. Further correction
requires a reviewed new variant with the old failure kept.

If strict translation succeeds, verify that its node body matches the
qualified predecessor up to explicit namespace/type identities, and prove
the new root loop with a prefix invariant and remaining-root measure. The
result must connect the actual generated wrapper to the original semantic
root traversal for every valid root list, including empty lists. Error and
ordering controls must test the original predicates, not a weakened model.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`. Use `apply_patch` for the
wrapper, tests and plan. Check `git diff --check` and review the exact IR diff.
Run the focused test module using either the existing transaction-circuit
build or a standalone offline probe whose library path is the actual file,
with tests enabled and the actual unchanged hegemon-field dependency. The
standalone probe is function-level evidence, not a complete production build.

Each compiler/extractor command must be in a new reviewed packet with exact
source/tool hashes, one job, at most five minutes, conservative sampled RSS
stops below 3 GiB and at least 20 GiB free disk. A Cargo/extraction packet may
use a separate 256 MiB scratch ceiling; Lean proof packets retain the 50 MiB
ceiling. These are measured engineering limits, not continuous OS quotas.
Never reuse a failed one-shot marker or expand limits automatically.

## Validation and Acceptance

Accept the code refactor only with successful focused regression tests and
a diff limited to the wrapper and tests. Source identity must be explicitly
refreshed for new extractions because the file changed, even though program
serialization and relation construction are untouched. Old extraction and
release-source receipts remain historical. Do not claim unchanged serialized
program bytes solely from code review; run the current program identity check
before a combined integration qualification.

Accept the native proof only after fresh strict compilation, exact standard-
axiom audit, independent premise/source review, negative controls, complete
input/output pin readback and retained archive verification. Production
remains disabled until concrete privacy, extractive soundness, complete
runtime/byte refinement, resource accounting and independent release gates
are all satisfied.

## Idempotence and Recovery

All scratch attempts are additive and one-shot. Preserve logs, failed outputs,
source versions and receipt identities. Do not delete old artifacts or modify
installed tools. If the wrapper or tests fail, make a scoped source correction
and create a new reviewed attempt; do not relabel the old run. No retry may
bypass a tool denial. Stop and ask when further work needs new authority.

## Artifacts and Notes

The unchanged-source Stage 7 receipt has SHA-256
`a22be43b2054922a30e50b24bed4fe9c9c8bdbf52cbe9e9666ab5c7fd699c887`;
its archive manifest has SHA-256
`d407a3301381863c8a1c751e76eed650550ea23f1cad1b19ad330700962ca651`.
Record new test, extraction, translation and proof receipts here as qualified.

Stage 8 failed receipt SHA-256 is
`fdb73b5e1b5023a53f0982651e57396c1bf95ab69a5c0297e7696e597237510d`.
Its Rust-test log has SHA-256
`5bdd5481711dc2667b505e7b3695cadcc523cb3c5c750515a5b7fe136b66db89`;
the 818,538-byte LLBC has SHA-256
`77fcbfc2331b327e87c287e15ad1b368c66147c040a512c5fa9f216a2a1876c6`.
The exact 526-file / 81,085,198-byte archive is
`.agent/artifacts/smallwood-poseidon2-v8/native-root-loop-tests-fdb73b5e1b5023a5`,
copy-manifest SHA-256
`511078f2e98b381388d0f6ce7aae845dfc018ca84c2a4c3f900b8318e6e6e4ac`.
Independent readback verifies the exact 526-file set, every size/hash,
the current source copy, unchanged failed receipt and absence of symlinks.

Stage 9 failed receipt SHA-256 is
`743f8fa933c95187a9d4f7a1e246dc252b29439546418e627c399eb1a8600951`;
the translator log has SHA-256
`fabf03b2fe1dc826da29d756cfc045ef449bc7368954519642f38449456d0ac6`.
The bounded run lasts 2.94 seconds with 12 resource samples, maximum sampled
group RSS 71,598,080 bytes and maximum scratch allocation 6,139,904 bytes.
All three ordinary and 3,719-record frozen-candidate inventories are exact;
the owned group exits 2 and is extinct without signals. Preserve the exact
28-file / 7,986,269-byte archive at
`.agent/artifacts/smallwood-poseidon2-v8/native-root-translation-failed-743f8fa933c95187`,
copy-manifest SHA-256
`331c12578469a1999057c4872fe6b0e565e68440c8f2d59ab641f49f3f634e80`.
Independent readback verifies every source and retained size/hash, exact
payload set, both failed receipts, raw LLBC and absence of symlinks.

## Interfaces and Dependencies

The public Rust function signature remains
`(&SmallwoodPoseidon2V8ExpressionProgram, &[u64], &[u64]) -> Result<Vec<u64>, &'static str>`.
The output element and error contracts remain unchanged. No new dependency
is needed. The production capability remains `None`; no registry, runtime
gate, proof envelope, relation compiler or deployment is changed here.

Initial revision: choose a local, reviewed implementation refactor with
explicit element/error-equivalence boundaries to resolve the four concrete
stdlib-model gaps without inventing replacement library assumptions.

Stage 8 revision: record successful finite tests and clean extraction-command
exit separately from the failed type-inventory screen. Preserve the original
failure and require a new strict-translation decision on exact reviewed bytes.

Stage 9 revision: retain the strict translator invariant failure and complete
postflight without retry. Diagnose the concrete lifetime-erasure constructor
and checker mismatch before preparing any new isolated candidate; no invariant
may be disabled and no existing frozen binary may be changed.
