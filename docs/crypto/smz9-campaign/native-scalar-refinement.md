# Actual Rust scalar refinement: subtraction, addition and multiplication

Status: checked isolated source-extraction results, 2026-09-08 UTC. These
three helper theorems advance R0; they do not close whole-evaluator,
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
Lean 4.32.2 integrated 745-root gate. Existing unrelated native-decision
declarations in the imported Hegemon module do not occur in the credited
roots' axiom dependencies. These helper results leave the actual inverse
loop, expression-array induction, indexing, shifts, canonical admission,
runtime builder/array binding, ordered root collection, acceptance pipeline,
and binary correspondence to be proved. Full R0 and concrete P7/K8 remain
open; release authority is unchanged.
