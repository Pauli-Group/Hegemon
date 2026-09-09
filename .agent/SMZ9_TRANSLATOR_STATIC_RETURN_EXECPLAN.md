# Qualify consistent concrete lifetime erasure in a new translator candidate

This living ExecPlan follows `.agent/PLANS.md` and continues
`.agent/SMZ9_ROOT_COLLECTION_REFINEMENT_EXECPLAN.md`. It owns only a new
isolated translator candidate, controls and related local evidence. It does
not authorize editing existing frozen tools, Rust, generated proof files,
dependencies, production gates, or publishing anything.

## Purpose / Big Picture

The actual SMZ9 node evaluator returns either node values or a static error
string. Its root-wrapper translation fails before root collection because
the translator's concrete-value representation requires every lifetime to be
erased, while one return-value constructor preserves static lifetimes.
Correcting this representation boundary with all type checks intact lets
strict translation be tested again on exact current Rust-derived input.
A translator build or successful finite controls are not themselves a native
refinement proof or a production authorization.

Here a symbolic type retains lifetime information for borrow analysis; a
concrete value's type erases it. `RStatic` is a static lifetime, `RVar` a
lifetime variable and `RErased` the concrete representation. Charon's
`Substitute.erase_regions` replaces variables only. Aeneas's existing
`TypesUtils.ty_erase_regions` replaces every lifetime. Neither helper is to
be globally redefined.

## Progress

- [x] (2026-09-09) Retain and independently verify failed Stage 9 receipt
  `743f8fa933c95187a9d4f7a1e246dc252b29439546418e627c399eb1a8600951`.
- [x] (2026-09-09) Trace LLBC statement 37's node call into the actual return
  constructor and the next statement's unchanged typing check. Independently
  inspect the constructor, checker and lifetime-erasure definitions.
- [x] (2026-09-09) Review concrete-versus-symbolic use sites and explicitly
  preserve the stronger static-sensitive symbolic comparisons at invariant
  lines 411 and 678-679. An initial broader review recommendation was rejected.
- [x] (2026-09-09) Copy the exact 2,311-record / 14,485,255-file-byte source subtree into
  new scratch; independently check every literal symlink and regular byte.
- [x] (2026-09-09) Apply exactly eleven line replacements in five copied source files,
  retaining all assertions, control flow and earlier two projector fixes.
- [x] (2026-09-09 04:48 UTC) Review the one-shot Stage 10 packet and pass
  all 28 mock/read-only controls. The approved build stops on an unmodeled
  Dune action-sandbox symlink; retain failed receipt
  `fe7de8169930e6d910e4d7fe434854822c15e4d41b6a9992a64ed9fa701a01ff`.
  One delivered SIGTERM leaves the owned group extinct and reaped. Neither
  compiler exit status nor immutable postflight completion was recorded;
  cleanup success is not compiler success.
- [ ] Review and qualify a separate fresh Stage 10 R2 build selecting the
  installed Dune's documented `--sandbox=copy` mode. Preserve the OS sandbox,
  symlink rejection, limits, source patch and failed Stage 10 packet.
- [ ] Qualify actual-constructor positive and malformed-type negative
  controls against separately linked old and new libraries with checks on.
- [ ] Strictly translate current wrapper input and compare old arithmetic/
  node output fixtures under a separately reviewed bounded packet.
- [ ] Retain exact outputs and independently verify them before returning
  to generated Lean-source review and native wrapper refinement.

## Surprises & Discoveries

The failure's source span is the StorageDead statement immediately after
the call, not `Try::branch`; rewriting `?` as `match` would keep the same
failing boundary. The log does not identify the exact failing context binding,
so this is a source/LLBC-grounded constructor mismatch rather than a printed
runtime-value trace. The old projector controls constructed their own
already-erased concrete values and did not exercise the actual constructor.

A one-line constructor repair is insufficient: the symbolic-to-concrete
expected-type calculation at `Invariants.ml:536` uses the same narrower
operation. Conversely, erasing static lifetimes in symbolic-to-symbolic
comparisons at lines 411 and 678-679 would lose a distinction they currently
check. Those comparisons remain byte-for-byte unchanged.

## Decision Log

Use a new source tree at `/private/tmp/smz9-static-return-stage10.uwb4z6iA`.
The old candidate is immutable at
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage5-erasure-candidate`.
Copy its `sources` subtree with literal links, not its compiled build tree.
Its exact source inventory has 2,047 regular files, 236 directories and 28
symlinks. The two build-relevant links remain internal; documentation links
may be dangling and are recorded literally, never traversed by inventory.
No new dependency or tool installation is needed.

Make only these eleven line replacements, from the local frozen predecessor:
`llbc/ValuesUtils.ml:82`, `interp/InterpUtils.ml:168`,
`interp/InterpProjectors.ml:21,391,407`,
`interp/Invariants.ml:532,536,633,675,691`, and
`interp/InterpStatements.ml:1451`. Replace the qualified variable-erasure
calls on those lines with `TypesUtils.ty_erase_regions`. All files are under
the copied `sources/aeneas/src`. Keep every equality, predicate, branch,
error, symbolic value and region-bearing type unchanged. Existing projector
corrections at lines 108 and 261 remain. Preserve Charon substitutions,
static-sensitive global handling, invariant lines 411 and 678-679, and the
copyability predicate. This bounded candidate is not a global lifetime-model
repair and must be rejected if its controls or strict translation fail.

Stage 10's default Dune action sandbox created an internal dependency
symlink under `build/.sandbox`; the resource guard rejected it after 12.43
seconds, and the same guard prevented recorded immutable postflight.
Independent read-only reconstruction subsequently verifies all 3,719 frozen
records, 2,312 new source records, 4,932 Python records, 10,787 installed
artifact records, eight loader chains, 21 file pins and seven packet pins.
That separate check does not retroactively make the failed receipt pass.
The installed `man/man1/dune-build.1:49-50` documents `--sandbox=copy`;
actions requiring another sandbox mode may override it. Test this in fresh
scratch `/private/tmp/smz9-static-return-stage10r2.raN1Pz91` with unchanged
source and a separately frozen packet. Do not allow arbitrary build symlinks
or disable macOS `sandbox-exec` to accommodate the build system.

The native compiler build has a separate 768 MiB scratch ceiling, a 736 MiB
conservative stop, one job, 250-second child stop and 300-second total bound.
The compiled predecessor occupies about 314 MiB, while its source files total
about 14 MiB; this motivates a build-specific budget but is not a prediction
of the new build's peak. Require at least 20 GiB free and sampled group RSS
below 2.75 GiB, with a distinct 3 GiB waited-child peak ceiling. These are not
continuous OS quotas. A build profile may retain the previously qualified
local Unix-socket exception needed by Dune; Internet networking remains
denied and child writes are limited to fresh build/tmp/cache outputs. That
exception is an explicit host-IPC boundary, not complete network isolation.

## Outcomes & Retrospective

The fresh source copy matches all 2,311 predecessor records before editing.
Exactly eleven lines in five copied files are changed through apply_patch;
the complete diff preserves every assertion and the identified stronger
symbolic comparisons. No compiler execution, repaired translator, successful
control, generated proof or release is claimed yet. Stage 8 and Stage 9
failures remain retained.

## Context and Orientation

The frozen predecessor has executable SHA-256
`b2ea49f1ac27930e20dc19f430b7ca4f5284119fe322f4addeaac0e1c1e0de37`.
Its full 3,719-record source/build manifest is
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage5-r3-fixture/FROZEN_R2_TREE.json`,
SHA-256 `4d0f5c54fb9f71eac5ceda041f7be8f84745ea003dfa137b98a369e3b64351ce`.
Use the already installed isolated OCaml switch at
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/ocaml-switch/_opam` read-only.
The actual current root input is
`/private/tmp/smz9-root-loop-stage8.lJ1IJ4K5/out/program.llbc`, SHA-256
`77fcbfc2331b327e87c287e15ad1b368c66147c040a512c5fa9f216a2a1876c6`.
Its exact embedded IR source is still
`a580c88243eb6551e60b28c07f57c7ab6b3d3c44f8c007361568d1726fa1bd47`.

## Plan of Work

First copy only the frozen source subtree to the fresh root, preserve its
literal records, and apply the eleven replacements through apply_patch.
Compare every copied record against the frozen manifest with only the exact
eleven-line exception. Freeze new source hashes before any compilation.
Prepare a runner that revalidates old inputs, new source, installed tools,
loader chains and packet bytes before launch and after success or failure.
Reuse the reviewed owned-process-group cleanup without importing old stage
state. No build may start until complete coordinator and independent review.

Next link a new control source separately against old and new libraries.
Exercise the actual constructor and fresh constructor on scalar, free-region,
static-reference, nested actual Result, mixed nested and static-array types.
Require exact concrete type, unchanged symbolic identity and type, and the
full enabled invariant checks. The old baseline must expose the static
constructor failure. The new candidate must pass those positives and still
reject malformed runtime types and inconsistent symbolic static/free types.
Do not swallow arbitrary exceptions or disable checks to complete controls.

Only after those controls qualify, translate the current wrapper with strict
checks enabled. Require exact output inventory and successful postflight;
compare old supported fixture output bytes to their retained counterparts.
Any failure remains a failed bounded candidate, not permission for an
unreviewed retry, a missing-model stub or a production capability.

## Concrete Steps

The build command is the frozen switch's absolute `dune` executable followed
by `build --root NEW/sources/aeneas/src --build-dir NEW/build --profile release
--display short --no-config --disable-promotion --cache=disabled -j 1 main.exe`.
Here `NEW` means the exact Stage 10 path above; the reviewed runner supplies
an explicit sandbox profile and minimal environment. Do not run a shell with
placeholder paths. The expected output is `NEW/build/default/main.exe`.
Subsequent control compilation and translation require their own reviewed
exact argument arrays and input hashes, not ad hoc commands.

## Validation and Acceptance

Source acceptance requires the exact copied set, bytes, literal symlinks and
only the eleven approved line replacements. Build acceptance requires zero
exit, complete input/output records, owned-group extinction and all resource
boundaries. Qualification additionally requires enabled positive/negative
constructor controls and strict translations; build success alone does not
qualify the candidate. Native proof qualification remains a later stage with
fresh Lean compilation and standard-axiom auditing.

## Idempotence and Recovery

Use fresh additive packets and exclusive one-shot markers. Preserve old
trees, receipts and failures. Never delete a marker, relabel a run, mutate
installed tools or increase a failed run's limits automatically. An owned
group whose extinction is unconfirmed blocks further execution. A tool denial
must not be bypassed; K8 is outside this work.

## Artifacts and Notes

Record copied-source, patch, runner, build, control, translation and retention
hashes here as they become qualified. The controls draft has separate ownership
under `/private/tmp/smz9-static-return-controls.B5XbH3wN`. It is preparation
only until its complete source and execution packet are reviewed.

## Interfaces and Dependencies

The Rust program and its error behavior remain unchanged. Symbolic types
still retain static/free regions for borrow analysis; concrete tvalue types
use the already existing all-region erasure function. The candidate changes
no production dependency or cryptographic primitive. Translator/compiler,
system-library and platform correspondence remain engineering assumptions.

Initial revision: define a concrete-only representation correction with
stronger symbolic comparisons preserved, actual-constructor controls and
explicit isolated native-build resource and local-IPC boundaries.

2026-09-09 update: retain the failed build and separate successful read-only
input reconstruction; prepare a distinct documented copy-sandbox build,
without changing the source correction, OS sandbox or resource boundaries.
