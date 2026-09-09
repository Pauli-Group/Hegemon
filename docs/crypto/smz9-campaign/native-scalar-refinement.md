# Actual Rust scalar and node-evaluator refinements

Status: checked isolated source-extraction results, 2026-09-09 UTC. Four
helper refinements, all ten node constructors, and the complete canonical
node-array loop are checked, including actual empty witness rows for
public-only programs. These results advance R0; they do not close program
root collection, acceptance, binary or cryptographic refinement. The node
subject has exactly two explicit kernel-proof arguments, as detailed below.

## Exact statements

The selected source is the unchanged
`circuits/transaction/src/smallwood_poseidon2_v8_ir.rs`, SHA-256
`608786dc9232c22612da6ce4e13bab4fdfe354be2065cdc08227a9ceff618454`.
The first scalar receipts import their target definitions unchanged from
`formal/lean/Hegemon/Transaction/Poseidon2V8RelationProgram.lean`, SHA-256
`a4c9714d6a8d21b0ffe1e1539d838917fb505708f2c0fde4f30fb222ba0151a9`.
The later node-body closure rebuilds the current metadata-only source revision,
documented below, rather than silently rebinding those earlier receipts.
Charon extracts the actual selected source bodies and Aeneas emits the Lean
functions against which the proofs run. Neither generated functions nor
target field definitions are replaced by handwritten substitutes.

| Source helper | Quantification and checked conclusion |
| --- | --- |
| `sub`, lines 435–441 | For every pair of actual backend `U64` values below the original modulus, execution succeeds, returns a canonical word, and its natural value equals the original `fieldSub`. |
| `add`, lines 430–432 | For every `U64` pair, with no canonical-input restriction, execution succeeds, returns a canonical word, and equals the original `fieldAdd`. |
| `mul`, lines 444–446 | For every `U64` pair, with no canonical-input restriction, execution succeeds, returns a canonical word, and equals the original `fieldMul`. |

The main roots are
`Smz9IrSubRefinement.sub_canonical_refines_actual_fieldSub`,
`Smz9IrAddMulRefinement.add_all_u64_refines_actual_fieldAdd`, and
`Smz9IrAddMulRefinement.mul_all_u64_refines_actual_fieldMul`.
The extracted modulus equals the original Goldilocks modulus. The proofs
establish actual checked integer success, not just field congruence: every
U64 sum/product fits U128, the positive-modulus remainder is below
`18446744069414584321 < 2^64`, and the narrowing cast preserves that value.

Subtraction genuinely needs its assumptions. Three additional kernel-checked
roots establish that `(p,0)` returns the noncanonical word `p`, that this
violates canonicality, and that `(0,p+1)` fails with integer overflow. These
are assumption-boundary tests, not evidence that an admitted proof reaches
those raw inputs.

## Evidence and reproducibility

The retained local evidence directory is
`.agent/artifacts/smallwood-poseidon2-v8/native-refinement-scalars-v2-4050e54ee1c381c4`.
It contains the unchanged generated Types/Funs, both proof sources, LLBC,
symbol inventory, provisioning/handoff records, fresh compiled modules and
raw logs, and the v2 checking script and receipt. Its receipt SHA-256 is
`4050e54ee1c381c456bc0c999bf9864f99cb8e614fcfd9df3e375ba37561e840`;
the checking script SHA-256 is
`88d5b7f26f7fb7142a9371259ff59dc73d409de346cf2b34ea787dfa134e1195`.
This directory is ignored evidence, not a production manifest or activation.

The original reproducible invocation is
`python3 /private/tmp/smz9-native-tools.lS4uVwgg/verify_scalar_v2.py`.
It requires a fresh `proof-v2` output directory and does not overwrite the
completed receipt. The retained copy is an evidence archive, not a
self-contained relocatable runner: original paths and pinned dependencies
are recorded in its provisioning and receipt files. Its proof sources are
both stored under `proof-src`; the receipt preserves their original paths.

V2 performs eight fresh strict import builds: the four unchanged Hegemon
modules `Bytes`, `NoteCommitmentInputs`, `Poseidon2Width16Kernel`, and
`Poseidon2V8RelationProgram`, plus both generated Types/Funs pairs. It then
checks both proof modules using Lean 4.31.0 with
`-t 0 -j 1 -M 2800 -DwarningAsError=true`. All ten subprocesses exit zero.
Source/LLBC pins and the consumed fresh import `.olean` hashes agree before
and after the checks; these Hegemon/generated imports resolve only through
the new v2 build directory.

The evidence gate enforces all nine exact qualified roots once each, with
exact axiom sets: eight use only `propext`, `Classical.choice`, and
`Quot.sound`; the standard widening root uses only `propext` and
`Quot.sound`. No credited root uses `sorryAx`, `Lean.ofReduceBool` or a
custom axiom. Five evidence-string controls accept the correct log and
reject renamed, duplicate/omitted, extra-root and added-axiom variants.
The final proof checks take 2.022 and 1.835 seconds; peak child RSS across
the serial v2 run is 2,229,993,472 bytes, approximately 2.077 GiB.
Independent review found no remaining arithmetic or exact-root/import-pin
issue. The external transitive library closure is not fully sealed: this is
not a hermetic build claim.

## Actual inverse: separately checked v3 extension

The unchanged source `inverse` (IR lines 448–463) now has a checked
refinement for every canonical U64 input, including zero. The original
generated loop remains the theorem's subject. Its stronger root
`Smz9IrInverseRefinement.inverse_loop_refines_pow` proves successful
termination for arbitrary U64 exponent and base with a canonical accumulator,
returning exactly `(accumulator * base ^ exponent) % p` as a canonical word.
The actual low-bit/parity relation and checked signed right shift by one
give strict decrease of `exponent.val / 2`; a modular square-and-multiply
invariant gives the exact value. The generated multiplication is
definitionally equal to the frozen v2 generated body.

`inverse_canonical_refines_actual_fieldInverse` then establishes successful
`p-2` initialization and equality to the original imported total `fieldInverse`.
There is no nonzero-input premise. This proves the existing power-based
definition, not a new primality/Fermat theorem or multiplicative-inverse law.

Three strict v3 builds freshly compile inverse Types/Funs and the unchanged
proof, with the same single-worker flags and exact binary as v2. Five exact
unique roots have only the three standard axioms; all five evidence-string
controls pass. The consumed frozen v2 sources, generated imports, compiled
proofs, receipt and checking script are pinned before and after. The inverse
proof check takes 2.809 seconds; peak serial child RSS is 2,232,811,520 bytes
(approximately 2.08 GiB). Coordinator and independent read-only review found
no mathematical, exact-root or retained import-provenance issue.

The separate local archive is
`.agent/artifacts/smallwood-poseidon2-v8/native-refinement-inverse-v3-29670ce01aeadeb0`.
Its strict receipt SHA-256 is
`29670ce01aeadeb026f308dd5211512ebbd3798c9e8115cb01e695e06920395c`;
its proof SHA-256 is
`2bef8e3d2532f69193426e63a87fa0b3b6fde8f5e5fe0ed37bd15a3a829c2c16`.
This extension depends on the frozen scalar-v2 evidence and the same explicit
translation/standard-library trust boundary; it is not a hermetic runner.

## Explicit trust and unfinished work

The pinned pairing is Aeneas
`8d58d14ad655b3d871af1038c203c3f524ab4df9`, Charon
`b82d2748c1e5bfd9519cd9401f9186d33b44a7f1`, Rust nightly 2026-08-18
`8fa1c96cfd489e4c27654c144ae871ce2c4db6c6`, and Lean 4.31.0 on aarch64
macOS. Translation/compiler correctness and Aeneas integer semantics remain
trusted engineering assumptions. The scratch Cargo manifest points directly
to the original IR and actual field crate; it does not prove equivalence to
the complete production Cargo configuration or machine code.

U64-to-U128 widening uses Aeneas's concrete standard-library `From` model.
An additional extraction successfully exposed the actual Rust `From` MIR,
but its generated Lean failed with six pure-value/monadic-result type errors.
That unedited failed variant is retained separately and is not credited.
No source-proved Rust standard-library conversion is claimed.

The isolated Lean 4.31.0 results are not silently added to the repository's
Lean 4.32.2 integrated gate. Existing unrelated native-decision
declarations in the imported Hegemon module do not occur in the credited
roots' axiom dependencies. These helper results leave expression-array
induction, generic indexing/bit shifts, canonical admission,
runtime builder/array binding, ordered root collection, acceptance pipeline,
and binary correspondence to be proved. Full R0 and concrete P7/K8 remain
open; release authority is unchanged.

The unchanged node evaluator successfully extracts to transparent Charon
LLBC, but unmodified pinned Aeneas fails at `InterpProjectors.ml:109` before emitting
Lean. Source inspection points to inconsistent region erasure of the static
error-reference return; the later isolated instrumentation confirms retained
nested RStatic versus recursively erased RErased at the assertion. The failed extraction and source-derived
diagnosis do not constitute an evaluator proof; no generated function or
Rust signature was substituted.

## Independently built, unmodified translator baseline

At 2026-09-08 06:35 UTC, the exact pinned Aeneas/Charon source pair built
successfully with one native Dune job in an isolated local OCaml switch.
The build took 215.77 seconds and the complete replay/postflight stage took
264.37 seconds. The original nodes LLBC again exited 2 at projector line
109, through `apply_proj_borrows` during backward-return synthesis, with
no generated Lean files. All three scalar LLBC replays succeeded and their
six Types/Funs files were byte-identical to the earlier credited outputs.
The node failure is an expected negative baseline result, not successful
evaluator extraction.

The native ARM64 executable has SHA-256
`63cb15a3d10b031ca824b26669762eecc15d348429d0741c94bab9dd0fc7de70`
and reports `aeneas 8d58d14-local-baseline`. It dynamically links the pinned
local GMP and zstd libraries and is not a self-contained or release-byte-
identical binary. The single-use runner, exact specification, sandbox
profile, full logs and receipt remain under
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage3-baseline`, with supporting
control files in its parent. Receipt SHA-256 is
`a9c8fff7cdc74fe48692f06d4e14d90024085e8afad4aa42535fd294c7617cde`;
the build log is
`d03b2ddd81210944f54e57d9eda2b9c1a8fff4089a3e5480ad442024c62213b9`.

Preflight and postflight check the exact source commits and trees, complete
Aeneas/Charon source inventories, 10,787 installed-artifact records, two
actual native-library identities, four original LLBC inputs, six retained
scalar outputs and the older release translator. Child writes are limited
to the new stage's five output/build/cache/temp/log directories. External
networking is denied; only the reviewed local Unix IPC for Dune is allowed.
Maximum sampled total acquisition-root size was 1.902 GiB and minimum
sampled APFS available space was 17.161 GiB. No resource stop or sandbox
denial occurred. The dependency installation had previously been interrupted
during cleanup by its fail-closed directory-size check; its separate
postflight verified all 118 exact installed packages and executable tools.
This baseline did not retry or relabel that installation as exit-zero.

Any instrumented or corrected translator must use distinct source/build
outputs, preserve this baseline, retain its assertion and strict translation
flags, and replay the unchanged inputs. No such correction is credited by
this baseline milestone, and no whole-evaluator or R0 receipt is filled.

## Isolated two-site translator candidate

The subsequent instrumentation-only run preserves the assertion, reproduces
the original failure and keeps all six scalar outputs byte-identical.
The separately reviewed candidate changes only the two projector-side
expected-type erasures to the existing recursive type eraser. Original
source trees and all baseline/instrumentation evidence remain unchanged.

At 2026-09-08 08:40 UTC its one-job native build passes in 228.981 seconds.
The built executable SHA-256 is
`b2ea49f1ac27930e20dc19f430b7ca4f5284119fe322f4addeaac0e1c1e0de37`.
The test harness then fails compilation at line 14: OCaml infers its
unannotated concrete record as evalue, whose constructors exclude VSymbolic.
No control execution, node/scalar translation replay or checks phase runs.
All ten owned process groups exit and the failure is retained separately.

The R2 execution receipt at
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage5-erasure-candidate/R2_EXECUTION_RECEIPT.json`
has SHA-256
`ab1fff5d7140fe54100fca4fb3486b13121caeedf3a7e0515da7e0442a1fc1a2`;
its incomplete status is intentional evidence of the stopped run.
The original failed receipt is not superseded or relabeled by the following
successful fixture correction.

## Corrected fixture replay succeeds

At 2026-09-08 09:04:23 UTC the separately reviewed R3 final replay passes
in 104.444 seconds, reusing that exact frozen candidate without rebuilding
or copying its sources. The only fixture change types `concrete` explicitly
as `symbolic_value -> tvalue`. All 21 exact projector/caller cases pass
normally and again with the checks flag enabled. The unchanged nodes LLBC
translates successfully in 1.552 seconds; its separate `-checks` replay
passes in 3.351 seconds and emits byte-identical output. All six scalar
Types/Funs outputs remain byte-identical to their prior reference files.

The strict node output contains exactly `Smz9IrNodes/Code/Types.lean`
(41 lines, SHA-256
`967c5caff2863178b7e7c186eab7d15fdde9305b65183bdd5966002fb3ed735c`)
and `Smz9IrNodes/Code/Funs.lean` (269 lines, SHA-256
`4ee3ecb61af8975930f6c1b685623684ef1f8b479bf652f78277dc7519987391`).
There are no generated placeholders or external/template replacements.
The execution receipt is
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage5-r3-fixture/R3_FINAL_EXECUTION_RECEIPT.json`,
SHA-256 `160a4268af0dc92c29b65fe04a34aa6542d4af4b202b8addd2d5e736532f213c`.

All 24 owned process groups are extinct without signals. Full postflight
revalidates original/copied sources, installed/native libraries, retained
inputs, Stage4/R1 evidence, all 3,719 frozen R2 tree records and prior R3
preparations. The earlier R3 launch-profile error and revised-preparation
log-name collision remain preserved as separate pre-execution evidence.
Maximum observed root allocation is 2,721,320,960 bytes and minimum free
space is 17,647,124,480 bytes. The checks phase takes 10.174 seconds within
its separate 600-second bound; no resource stop occurs.

This stage provides successful translation and finite regression evidence,
not expression-evaluator refinement. The finite controls'
checks flag does not explicitly invoke whole-context invariant validation;
the separate node `-checks` replay remains a distinct, still finite check.
Translator correctness, actual-array induction, acceptance and full R0 are
still open.

## Generated node definitions compile; body proof remains unverified

On September 8 the isolated `initial-r2` check successfully compiles the
exact generated Types and Funs with Lean 4.31.0. All three version/compile
commands exit zero in 33.6677 seconds, with before/after source and dependency
checks and no live child groups. Its receipt SHA-256 is
`d59414732d885a8812ee52971751cf1eca2bdbf72401c24fae08a30ca747c0ed`
at `/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage6-nodes-lean.fbqPGn/initial-r2/INITIAL_COMPILE_RECEIPT.json`.
The earlier missing-search-root preflight failure is preserved separately.

Independent review of the proposed 440-line proof's V2 runner found incomplete
directory-symlink guards, an unpinned loaded resource-policy file and a missing
final historical peak-RSS assertion. V2 execution was withheld. A separately
reviewed V3 corrects those guards. Its actual preflight passes two positive,
seven malformed-axiom and four path/link controls, then rejects a source-pin
change before launching Lean. The failed receipt is preserved at
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage6-nodes-lean.fbqPGn/body-proof-v3/RECEIPT.json`,
SHA-256 `47f69f3e5d4a7289c0e16e263beca9feb49b597a5c4b296ecc1e70f7e6f3248b`.

The changed source is `Poseidon2V8RelationProgram.lean`: commit
`dfd720527c5a6be546c21388716983e9b92274d3` changes only its three program-identity
constants, leaving field/evaluator definitions unchanged. Its current SHA-256
is `170cd4e999b08445cf46c7abde03aefd8790b567f6d04ca5d84bfb62d8616a9d`.
The scalar/inverse receipts above remain historical checks against their
original pinned source; they are not silently rebound. A distinct V4 executes
a fresh build of all four current Hegemon modules, eight unchanged generated
modules, three unchanged scalar/inverse proofs and the original node-body
proof. None of the old Hegemon/generated/proof output directories enters its
import search path. The first fifteen compilations pass, including exact
scalar/inverse axiom audits; the final node-body proof fails on iterator,
let-pair and Vec-index proof simplification. Its failed receipt SHA-256 is
`2a7f6a9ba8d3b6597aad665d3d6b80c06563270e2180d641c6f2aea8761884ae`.

The failed proof also exposes two native-decision axioms from the generated
body's implicit error-string bounds. The unchanged Aeneas `toStr` definition
supplies those bounds using `decide +native`. Because Lean audits dependencies
in theorem types as well as proof terms, merely improving the downstream proof
cannot remove the original body constant's dependency. No body theorem is
credited from this run.

A separate V5 candidate attempts exactly two explicit `(by decide)` arguments
at the existing `toStr` calls, but fails because `U32.max` requires its defining
equation. V6 uses `(by simp only [U32.max_eq]; decide)` at those exact two sites.
Both concrete ASCII-bound roots compile with only `propext`, and the fresh
derivative compiles. The earlier proposed no-axioms claim is not achieved;
the permitted-standard-axioms gate is unchanged. An exact text validator
rejects any other generated-code change. Rust, LLBC, translator, libraries
and original generated source remain untouched. This is a proof-argument
derivative, not byte-identical generated output or a theorem about the old
elaborated constants.

V6-V9 preserve failed mechanical proof simplifications. V10 is uncredited:
the coordinator invokes system Python rather than the previously used
Homebrew Python 3.14.5, and the process monitor lacks `os.waitid`. The harness
terminates the owned child; after the parent exits, a targeted PID/group
62665 query returns no process. No broad cleanup is performed. V11 restores
the qualified interpreter and verifies its required API before launch, but
catches a coordinator edit placed in Add rather than Bit. V12 starts from
the V9 proof and adds the single local let-unfold line only inside Bit.
All prior sources, receipts and logs remain failed, uncredited evidence.

The V12 check passes all 21 exact native node-body roots on the unchanged
V6 derivative. Every root uses only `propext`, `Classical.choice` and
`Quot.sound`. Two positive, seven malformed-axiom and four path/link controls
pass, as do the separate two-positive/seven-negative string-bound audit
controls. Complete before/after checks cover 136 pinned inputs and 16,797
dependency records. Peak child RSS is 2,249,539,584 bytes; elapsed time is
18.72 seconds, with one compiler job, M2800, a 3 GiB group cap, a five-minute
deadline and the unchanged cumulative 50 MiB packet limit. Its receipt is
`/private/tmp/smz9-aeneas-stage1.IgNKumAA/stage6-nodes-lean.fbqPGn/body-proof-v12/RECEIPT.json`,
SHA-256 `01aad797e0b92f0cb19e785168420a294e7b213f2a3de4710677b164fbc4d53f`.

## Complete canonical node-array loop

The V3 loop qualification passes its three main roots and six original-
predicate boundary controls. It derives every constructor's reads from
original `CanonicalAt true`, canonical inputs and concrete dimensions. Its
loop invariant preserves the actual expression slice, iterator/prefix length,
canonical words and exact remaining `evalExpressionNodes.go` computation;
the decreasing measure is remaining source-node count. The real empty vector
and zero iterator initialize the proof. An arbitrary Option-valued target is
preserved until success is concluded: execution success is not a premise.
Receipt SHA-256 is
`c27bf03d1d5d6aac062533da32ea2e04b2bb2ef7e2fea7ded2f9d0b78073d56e`.
The two earlier loop failures remain uncredited: a reserved binder name and
abbreviation rewrite, followed by a match-postcondition elaboration issue.

The V4 extension additionally qualifies the original `CanonicalAt false`
public-only domain. It generalizes only the witness-allowance parameter and
requires 686 rows conditionally when witnesses are allowed. The original
three true-case signatures remain exact corollaries. The public-only endpoint
passes the actual `Slice.new U64` to the native wrapper and `[]` to the
original semantic evaluator. No padded witness, native-success or semantic-
success premise is substituted. The proof also excludes every WitnessRow
constructor in that domain and checks the exact empty row value.

All 17 V4 roots pass the standard-only axiom audit, with 159 frozen input
pins and 16,798 dependency records revalidated before/after. The main loop
roots use `propext`, `Classical.choice` and `Quot.sound`; the validity/boundary
roots use only `propext`. Peak child RSS is 2,244,247,552 bytes and total check
time is 12.50 seconds under the unchanged one-job/resource/sandbox limits.
Receipt SHA-256 is
`a67299c94e885da8caf1c209bfdefe27ddc49e18c180ae12680f63440e382452`.

The 221-file / 29,208,236-byte exact evidence archive is
`.agent/artifacts/smallwood-poseidon2-v8/native-refinement-nodes-v4-a67299c94e885da8`.
Copy-manifest SHA-256 is
`1139e9f82b67f57016f36512d5cc10c02ca5d8b948196c79f7d3e4132f4a9bf2`.
Independent read-only postflight verifies the exact payload set, every size
and hash, the 17-root final receipt, and absence of retained symlinks.
It preserves original/derivative sources, successful and failed runs, compiled
outputs, logs, dependency manifests and externally pinned source inputs.
Negative-control symlinks are recorded rather than followed or recreated.
It is an evidence archive, not a hermetic replay or production manifest;
external toolchain/library dependencies remain pinned, not all copied.

Root-list collection and actual runtime-program binding remain open. In
particular, the retained LLBC has no declaration for
`evaluate_smallwood_poseidon2_v8_expression_program` or its program type;
embedded Rust source text is not an extracted function. That wrapper needs
a separately bounded extraction before an ordered-root proof. Empty-row
node evaluation is now checked, but this alone does not qualify complete
CSR residual evaluation, packed acceptance or full R0. P7, K8 and the
independent production/release gates remain unchanged.
