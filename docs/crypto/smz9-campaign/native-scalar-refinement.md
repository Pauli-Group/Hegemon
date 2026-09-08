# Actual Rust scalar refinements

Status: checked isolated source-extraction results, 2026-09-08 UTC. These
four helper refinements advance R0; they do not close whole-evaluator,
acceptance, binary or cryptographic refinement.

## Exact statements

The selected source is the unchanged
`circuits/transaction/src/smallwood_poseidon2_v8_ir.rs`, SHA-256
`608786dc9232c22612da6ce4e13bab4fdfe354be2065cdc08227a9ceff618454`.
The target definitions are imported unchanged from
`formal/lean/Hegemon/Transaction/Poseidon2V8RelationProgram.lean`, SHA-256
`a4c9714d6a8d21b0ffe1e1539d838917fb505708f2c0fde4f30fb222ba0151a9`.
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
LLBC, but pinned Aeneas fails at `InterpProjectors.ml:109` before emitting
Lean. Source inspection points to inconsistent region erasure of the static
error-reference return; runtime type instrumentation is still needed to
confirm that specific cause. The failed extraction and source-derived
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
