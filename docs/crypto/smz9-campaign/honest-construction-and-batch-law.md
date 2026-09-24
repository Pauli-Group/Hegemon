# Constructive honest rows and the exact batch law

These are forward constructions for the unchanged SMZ9 relation and sampler.
They do not fill the complete semantic or Rust-refinement receipts. The
arbitrary accepted-packed-to-typed endpoint already exists; the remaining
reverse direction must construct the actual honest assignment from the typed
witness and derive its acceptance, not assume an accepted packed witness.

## Typed replicated prefix

`SmallWoodV8Smz9SourceReplicatedRows` constructs rows 0 through 91 directly
from the fixed typed statement and witness. The two 34-row input blocks
contain value, asset and 32 position bits. The two 12-row output blocks
contain value, asset, six public ciphertext words and four private
authorization-key limbs. Each word is repeated in all 64 lanes, giving
5,888 words. Fixed semantic validity supplies canonicality and proves that
every bounded input, output, key and ciphertext access is a real list entry.
The constructor itself has no validity or acceptance argument.

Readback uses the original decoder's global `rawIndex`. In particular,
private note values occur at words 0, 2176, 4352 and 5120. Every word in the
arbitrary 38,016-word tail is preserved. This component neither fills that
tail nor uses default reads to assert full assignment correctness. The
position-bit formula is natural division/modulo, with machine-level U64
shift-and refinement still separate.

## Dense-range construction

`SmallWoodV8Smz9SourceDenseMaterialization` constructs the five rows 247 through
251 in their actual value-major order. Its 320 words contain 210 radix-four
digits, 46 zeros, seven high bits, and 57 zeros. Each value uses 30 low digits
and the bit above them. A general finite radix identity proves reconstruction
for every natural input; only the high-bit constraint needs the 61-bit bound.
The natural right-shift/mask identity is proved separately and is not presented
as extracted U64 execution.

`SmallWoodV8Smz9SourceDenseTyped` selects, in source order, input-zero value,
input-one value, output-zero value, output-one value, and encoded public words
44, 46 and 62. It derives their bounds from
`ExactV8RelationSemanticValid`: inactive openings are zero, active openings
have bounded values, fee is bounded, value-balance magnitude is zero, and
issuance magnitude has the stricter stablecoin bound. No accepted packed
witness or successful evaluator run is a premise.

The constructor is explicitly embedded after 15,808 words. Readback proofs
connect the local block to `denseDigitAddress`, `denseTopAddress`, and actual
`packedWitnessLaneRows` at rows 247 through 251. Reading a local 320-word block
at those global addresses would return default zeros; that is not the
construction used here. Data before and after the block remain arbitrary.

`SmallWoodV8Smz9SourceDenseRoots` derives the actual generated DAG formulas
for roots `1183 + 6 * slot` for the four low rows and root `1203` for the top
row. The concrete block makes all five roots zero in every one of 64 lanes.
These 320 field equations are conclusions of the proof.

`SmallWoodV8Smz9SourceDenseCsr` derives the actual generated sparse coefficient
DAG and all seven dense reconstruction residual formulas. Its intermediate
constructor leaves the four private raw cells explicit; only the three public
residuals vanish without binding those private cells.
`SmallWoodV8Smz9SourceDensePrefix` then supplies that binding constructively:
the typed 5,888-word prefix, an arbitrary 9,920-word authorization region,
the exact dense block and an arbitrary suffix are concatenated in source
order. All seven actual entries `15665..15671` have zero field residual,
with no raw-cell equality or typed-validity premise. This identity uses the
actual CSR coefficient DAG, not an assumed reconstruction equation. Both
arbitrary regions remain unchanged. The Option-based complete CSR executor
and the other 20,598 raw constraints are not proved by this component.

## Hash-block construction

`SmallWoodV8Smz9HonestHashMaterialization` takes 125 canonical 16-word live
initial states and constructs all 128 actual compressed traces. The last
three calls start at zero but still run the complete permutation. Each call
column contains 16 initial words, 150 S-box wires and 16 final words. Two
64-call groups transpose into the exact 364-by-64 block at rows 283 through
646. The proof derives canonicality, every initial/wire/final projection,
and the existing fixed `LeanHashKernelAccepted` predicate.

`SmallWoodV8Smz9HonestHashPlacement` places that block after 18,112 words and
uses the existing decoder initial/final indices and source S-box indices.
Its final coordinates equal the unchanged width-16 permutation. The first
final word of each dummy call is proved to be `0x60cffc11a095a4f6`, explicitly
showing that a dummy trace is not an all-zero block. An arbitrary 2,496-word
suffix gives the required total of 43,904 words; its content is not invented.

Five further modules, `SmallWoodV8Smz9HashReplayExistence`, `HashTraceSchedule`,
`HashSourceTrace`, `ComputedHashRoots` and `ComputedHashExecution` (each with
the same `SmallWoodV8Smz9` module prefix), prove forward satisfaction of the
actual generated hash roots. Strong-recursive replay satisfies the certified
strict earlier-row dependencies. Exact round scheduling identifies all
150 wires and 16 final outputs; placement transfers the recurrence to the
computed packed block. Every member of
`(exactNonlinearRoots.drop 471).take 332` is zero in all 64 lanes. These are
root-list positions, not expression-node numbers: 21,248 scalar equations
cover all 128 calls, including the three nontrivial dummy traces.

The interpreter endpoint runs the unchanged complete 8,271-expression DAG
and derives successful evaluation with `some 0` at each of those 332 roots.
Its named partial program changes only the selected root list. It needs
public length at least 120 and prefix length 18,112, but no presumed
recurrence, trace equality, root value or evaluator success. An arbitrary
suffix remains permissible because lane extraction pads missing words;
this does not establish full packed length or canonicality.

The generic hash-block theorem keeps 125 canonical live initial states as
component inputs. The typed constructor below now supplies them. Neither the
fixed hash-kernel predicate nor this exact partial-root theorem is substituted
for full acceptance. These hash and dense components alone cover 337 of the
830 root types; additional stable roots are established below.

## Typed authorization, inline rows and ordered hash schedule

`SmallWoodV8Smz9SourceAuthInputs`, `SourceAuthRows` and `SourceAuthReadbacks`
use the same module prefix and construct all 155 authorization rows 92..246.
Their 18 ordered families include mode flags, effective input PRFs and keys,
computed digests, counts and bitmaps, signer tags, membership flags and the
15 ordered pairwise tag-difference inverses. Every family coordinate and all
64 lanes have exact global readback. The generic component keeps a canonical
hash-final accessor explicit; composition below computes that accessor from
the same hash columns actually present in the assignment.

`SmallWoodV8Smz9SourceInlineRows` constructs the 31 rows 252..282. All 448
input/level/digest-limb slots have the actual previous-result, left, right and
direction fields, using the existing source index formula. Previous results
come from computed compressed traces; valid typed sibling and final-state
reads are proved present, not supplied by a default value. Policy rows use
the computed call-97 result in non-single modes, with exactly 57 zero padding
lanes per row. Row materialization alone does not establish their generated
binding constraints.

Five `SmallWoodV8Smz9TypedSchedule*` modules construct every one of the 125
live initial states directly from the typed transaction. They preserve the
fixed call roles and order, all inactive calls, source domain/length/mode/
suite preparation, final-block marker, full 16-word sponge carry, and actual
width-16 permutation. Nullifier helper digests needed before their scheduled
authorization calls are computed by the existing semantic sponge, not read
from a future uninitialized slot. The effective next accumulator retains
the current policy, intent, threshold and signer count while using the next
approval count and bitmap. Stable calls preserve the four padded configuration
chunks, configuration tree, before/after leaves, interleaved paths and issuer
calls, including disabled mode.

Fixed `ExactV8RelationSemanticValid` supplies source compression canonicality.
The resulting theorem equates each complete prepared frame with its raw
source projection using actual prior permutation results. Both dependencies
inside a call plan and the separate sponge-predecessor lookup are proved to
read only earlier calls. No entire-frame correctness, accepted assignment,
trace equality or successful evaluator result is an input premise. This is
a Lean source transcription reviewed against Rust; `initial_bindings` and
`final_binding` metadata and Rust execution identity are not proved here.

The three `SmallWoodV8Smz9SourceSpongeSegment`/`SourceAuthorization*`
modules additionally derive the actual contiguous sponge recurrence from
those source-call plans and the unchanged permutation. Fixed typed validity
supplies the precise input geometry, giving exact policy/current/effective-
next/value-lock digests at calls 97/100/103/105. The policy final equals the
stored current policy and is nonzero only in non-single-key modes; call
103 uses the source effective-next record, not unconditionally the raw next
record. These are derived digest identities, not assumed final-state values.

`SmallWoodV8Smz9SourceConstructedPrefix` concatenates the first 92 rows,
155 authorization rows, five dense rows, 31 inline rows and 364 hash rows.
Its hash-final accessor is read back from those same packed final cells.
`SmallWoodV8Smz9SourceTypedPrefix` instantiates that composition with the
typed schedule, removing the free live-state input. Fixed typed validity
gives `ExactWords 41408` for this 647-row prefix. All live packed initial
cells equal their raw source-frame words, with explicit `some`-entry proofs;
all live packed final cells equal the actual kernel on that source frame
and the scheduled final state. All 337 selected nonlinear roots and seven
actual dense CSR residuals transfer unchanged to this assignment.

The typed-prefix interface still accepts a caller-supplied stable tail;
`ExactWords 2496` for that tail gives canonical full length 43,904. This
conditional full-shape result is not full acceptance. The next constructor
supplies those 39 rows, with the remaining canonicality boundary explicit.

## Concrete stable tail

The five `SmallWoodV8Smz9SourceTail*` modules construct all 39 rows 647..685,
not an arbitrary auxiliary block. They compute the invertible 94-word private
reorder, parent public fields and spend keys; stable and authorization role
differences, first-nonzero selectors and inverses; all lifecycle, decimal,
capacity, epoch and collateral auxiliaries; 53 boolean slots, 46 numeric
slots, 33 multiplication lanes and all 1,434 radix-four digits. Eight ordered
families cover the full rectangle and have exact local/global readback.
The last 38 cells are zero padding; the leading 41,408 words remain unchanged.

The initial increment covered 27 of the 39 rows: the two source rows,
selector, inverse and 23 digit rows. The subsequent role/Boolean and
numeric/multiplication proofs now cover every remaining row. All 53 Boolean
values are actually 0/1. Numeric limbs and C operands use tight carry bounds
of at most `2^32-2`, with high limbs below `2^24`; decimal products are at
most `10^18`. Disabled auxiliaries retain same-epoch and
decimal-product units, the actual parent-height range and nonzero helper
operands; the disabled tail is not an all-zero assignment.

The tail constructor's only hash dependency is call 97. Its accessor must
be bound to the typed computed result when composing the full assignment;
canonicality alone does not prove the policy-digest identity or nonzero
role property. Natural subtraction and all-zero-role fallback deliberately
totalize cases rejected by Rust. Forward checked-success, range and active
nonzero proofs must eliminate those cases for valid inputs. No accepted
packed witness, arbitrary auxiliary values, or successful Rust run is
assumed to fill those obligations.

The separate checked-subtraction helper now derives the actual typed
decimal/cap/epoch and mint lifecycle inequalities and proves recomposition
of those computed auxiliary subtractions, including both retirement gaps.
It also proves epoch-gap/remainder/path-quotient bounds and that the bounded
three-factor products fit U128. This does not yet prove every range check,
final collateral borrow zero, multiplication equation or Rust execution.

## One full typed candidate and actual raw replication

`SmallWoodV8Smz9SourceFullTypedCandidate.fullTypedSourceCandidate` has only
the typed statement and witness as inputs. Fixed
`ExactV8RelationSemanticValid` proves `ExactWords 43904` for the full
candidate. There is no caller-supplied stable tail, live initial state,
hash-final accessor, auxiliary value, range admission or accepted-packed
premise. Public encoding canonicality is derived separately from the same
typed validity, not inferred from the candidate's size.

The complete candidate preserves every prefix word and exact stable-family
readback. The 94-word private reorder reads actual admitted entries; the
18 public source words start at 41502 and the eight spend-key words at
41520. All 125-by-16 initial/final cells use the same actual typed schedule
as the stable policy accessor. The 337 selected nonlinear roots and seven
dense reconstruction attempts hold on this very candidate.

Eight `SmallWoodV8Smz9SourceReplicate*` modules prove every one of the
15,561 actual raw replication attempts has zero interpreted field residual.
For index `i=row*63+lane-1`, the exact generated entry (including metadata)
is `attempt i 0 i 0 [(row*64+lane,1),(row*64,3)] 0`. Actual coefficient
node 3 is the literal canonical `p-1`, whose field interpretation is `-1`;
it is not a presumed subtraction expression. The constructor supplies equal
values in all 64 lanes of each of the first 247 rows, with no validity or
`EqualLanes` premise. The public field input and tail remain arbitrary.

Thirty-one ordinary-kernel slice certificates cover the complete actual
table prefix: thirty 512-entry slices and a final 201-entry slice. A
quotient/remainder proof gives a present exact entry for every `i<15561`,
then its mapped residual is `some 0`. No sampled table entry or native
decision axiom substitutes for this coverage. This component and the seven
dense attempts cover 15,568 of the 20,605 raw CSR attempts.

## Actual Merkle and stable-role equations

`SmallWoodV8Smz9SourceMerkleCopies` derives all 896 actual CSR entries
`16942..17837`: 448 copies of the computed previous digest and 448 copies of
the raw direction bit. Both operands come from the same constructor; no
copy-equality, lane-equality or validity premise supplies their equality.
The checked global-index metadata identifies actual table entries, and
coefficient nodes 1 and 158 are interpreted as 1 and -1.

Three `SmallWoodV8Smz9SourceMerkleInitial*` modules prove the 1,024 entries
`15918..16941`. The actual 64 calls include both inputs and every level,
including inactive inputs. Their 896 rate words use the same computed
previous finals and typed sibling orientation; 128 capacity words carry
domain 4 and the actual suite marker. Fixed typed validity supplies real
sibling/frame geometry. The final endpoint has arbitrary public coefficient
input and tail, so it instantiates directly on the complete typed candidate.
Wrong capacity, table index, coefficient and orientation controls each fail
for their expected semantic mismatch.

Three `SmallWoodV8Smz9Source*StableBooleanRoot*` modules derive actual root
805 and roots `807..829` on all 64 lanes of the complete candidate. The
Boolean row contains 53 actual bits and 11 zero-padding cells. The 23 digit
rows contain all 1,434 computed modulo-four digits and 38 padding cells.
Digit-root satisfaction needs no value-width admission; it does not prove
that those digits reconstruct every original value.

`SmallWoodV8Smz9SourceRoleAlgebra`, `SourceRoleNonzero` and `SourceRoleRoots`
derive roots 803/804, actual nodes 8009/8128, on the same candidate. The
selector has no validity premise. The inverse follows from fixed validity:
every actual role has a nonzero canonical limb, including distinct stable
commitment differences, the first active spend key, actual call-97 policy,
active signer tags and original unit padding. The complete 131-node source
slice and the exact interpolation formula are kernel-checked; a zero-role
control is proved to fail the inverse equation. No nonzero-role premise is
added to the final endpoint.

## Early, balance, inline, multiplication and policy-frame equations

Five `SmallWoodV8Smz9SourcePolicy*`/`SourceFullRatePreparation` modules
derive all 64 actual family-26 attempts `18715..18778`. They bind the
threshold, signer count and 30 tag words to the raw prepared call frames,
including capacity domain 7, length 32, suite, prior state and final padding.
No permutation-output cancellation or supplied frame equality is used.

`SmallWoodV8Smz9SourceInlineRoots` proves actual positions `121..128`:
seven orientation equations and the policy bridge. The bit comes from the
same constructed rows; non-single policy lanes use computed call 97 and
single mode derives the required zero gate. All 64 lanes are covered.

Four source multiplication modules derive root 806, actual node 8132 and
row equation `row660 * row661 - row662`. Every decimal, product, epoch,
carry-inverse and retirement lane comes from the full typed constructor;
inactive and padding lanes are handled explicitly. Actual parent height
comes from encoded public word 94. No multiplication-equation premise is
added to the endpoint.

Nine `SmallWoodV8Smz9SourceEarly*` modules derive actual roots `0..111`:
public Boolean/stable/reserved fields, all 64 direction bits, inactive
ciphertext limbs and note/stable asset membership. Four balance modules
extend this through `0..115`. Canonical distinct assets make the actual
interpolation weights exact indicators. Typed natural conservation supplies
the native fee, mint and burn branches; padding slots are proved zero
separately, without assuming padding conservation. The actual root list selects
each expression. The later metadata repair aligns the descriptive labels
without changing that executable root list.
Malformed Boolean/path/reserved/ciphertext/asset examples have nonzero
actual roots; nonzero fee/issuance with zero notes and duplicate assets are
separate balance controls, not admitted typed witnesses.

The next twelve modules add three exact forward subsets on this same
constructed candidate:

- Four `SourceTailCsr*` modules derive 496 actual raw attempts in families
  37, 39, 44, 46, 48, 49, 50, 51, 61, 84 and 85. Public compatibility copies,
  Boolean source copies and every selected padding value follow directly
  from construction, without a typed-validity premise.
- Three `SourceInactiveMerkleRight*` modules derive every actual family-17
  attempt at indices `17838..18285`. Fixed validity makes inactive inputs'
  position and siblings zero, hence every oriented right word zero; active
  inputs have zero gate coefficient. All 448 actual all-one controls yield
  residuals 1, 0 and -1 for public flags 0, 1 and 2.
- Five `SourceAuth*` modules derive nonlinear positions `129..251` and
  `449..470`, exactly 145 roots in all 64 lanes, including single-mode
  zeroing, actual interleaved PRF/key input bindings, mode selection and final
  zeroing. Final position 458 uses the actual next-count flag value 1.
  Six altered theorem controls fail for wrong root/order/mode/count
  bindings or missing typed validity.

The next 26-module increment derives 135 stable CSR residuals, 240
action-intent initial residuals, 48 dummy-initial residuals, 16 PRF-initial
residuals and 100 additional authorization roots from the same full typed
candidate. Initial-state results retain the computed prior hash states and
actual selected PRF key; dummy initial zero does not replace its final trace.

Seven subsequent role-CSR modules derive all 210 actual family-47 residuals
at globals `19344..19553`. Symbolic field term sums separate the algebra from
the full candidate; exact source/auth-family readbacks then instantiate all
accessors with the original typed candidate and its computed hash finals.
The 640 raw terms include all 168 explicit zero-coefficient terms. The final
endpoint needs only fixed typed validity and returns 210 distinct `some 0`
results through the actual generated attempt list.

Ten further authorization modules close the remaining 97 nonlinear positions
within `252..448`. `SmallWoodV8Smz9SourceAllNonlinear` composes the exact
indexed coverage of every one of the 830 roots in all 64 lanes. Its hash
slice proof obtains an actual bounded list element and proves membership;
an out-of-range default does not supply any root. The companion
`SmallWoodV8Smz9SourceNonlinearExecution` derives successful execution of
the complete unchanged expression DAG and reads `some 0` from every actual
root in its computed value array. Both endpoints require only the fixed
typed validity premise, not an assumed accepted packed witness or a supplied
interpreter result.

`SmallWoodV8Smz9SourceAuthDigestCsr` adds the 28 actual digest-copy attempts
from families 25, 30, 32 and 34, at globals `18708..18714`, `19019..19025`,
`19074..19080` and `19113..19119`. Each copy reads the same computed hash
final on both sides and retains the actual generated coefficients.
`SmallWoodV8Smz9SourceInlinePolicy192` adds all 21 family-27 bindings at
`18779..18799` and all 171 family-28 padding attempts at `18800..18970`.
The three live inline rows bind the policy word, computed call-97 final
and sum of the two non-single mode flags. The padding address
`17927 + 64*(index/57) + index%57` skips the seven live cells in each row.
Actual generated chunk membership supplies exact global lookup metadata;
all equations follow from the unchanged constructor without a validity
premise. Eight mathematical negatives test the three padding runs,
policy/final/mode operands, coefficient sign and exact count.

The next eight modules add 354 actual attempts. `SourceDense103` derives
the 46 dense-padding and 57 top-padding cells at `15674..15776` from the
actual dense constructor, not by treating packed addresses as coefficient
indices. `SourceBase7`, `SourceCipher12` and `SourceInactiveRaw92` add two
balance equations, five legacy-digest copies, twelve ciphertext copies and
92 inactive raw fields. `SourceAuthInitialFrames`, `SourceAuthInitialWords`
and `SourceAuthInitial128` establish the 48 current-accumulator, 48 next-
accumulator and 32 value-lock initial equations, preserving the exact
23-word and 14-word preimages and short final-block padding. Finally,
`SourceInputKeyCsr12` derives eight inactive-input-key equations and four
shared-key equations at `15777..15788`. Typed inactive keys are zero;
two active inputs have equal spend keys, while an inactive flag cancels
the actual shared-key coefficient product. Every final indexed endpoint
uses the unchanged full typed constructor and actual generated CSR entries.

Twenty-one further modules derive 290 actual attempts. Seven note modules
cover all 216 note-initial and inactive-preimage equations at
`15810..15917` and `18346..18453`, preserving the 18-word preimages,
three-block absorption and short final-block padding. Six nullifier modules
cover all 32 initial equations at `18300..18331`: the mode-dependent scalar,
the position reconstructed from all 32 bits, four rho words and ten frame
constants per input. Eight public-digest modules derive the actual note
and nullifier digests and the complete 32-step Merkle fold, then bind the
14 public roots, 14 nullifiers and 14 output commitments. Active input
spend-key selection is proved from typed validity; no accepted-packed
premise is used to obtain a forward source digest.

Fifteen further modules derive 332 stablecoin attempts. `SourceStableConfig112`
covers four configuration chunks and their three-node tree, including the
final chunk's padding. `SourceStablePath128`, `SourceStableLeaf32` and
`SourceStableIssuer32` cover both four-level paths, the two leaves and the
two issuer frames. `SourceStableDigestForward` and `SourceStableStateForward`
derive the computed configuration, state-root and issuer digests from the
actual scheduled kernel calls. `SourceStableOutputBindings` connects them
to typed transition equalities and exact public/private word encodings.
`SourceStableOutputCoefficients` executes the actual target DAG nodes;
`SourceStableOutput28` closes globals `20132..20145` and `20178..20191`.
Disabled transitions enforce before/after root equality without binding an
inactive hash; enabled root outputs and mint-only issuer outputs use their
exact gates. None of these endpoints assumes accepted packed data.

Ten range modules add all 66 actual family-60 reconstructions and 24
family-62 high-limb padding cells. `SourceStableRangeDigits` derives radix-four
reconstruction; direct and auxiliary bound modules supply the actual typed
source bounds. `SourceStableRangeTopBits` and `SourceStableRangeReadbacks`
bind the exact source digits and odd top bits to physical candidate words.
`SourceStableRangeCoefficients` executes the signed coefficient DAG;
`SourceStableRangeNatural` and `SourceStableRange66` close globals
`20192..20257`. `SourceStablePadding24` closes globals `20296..20319`,
using the six separate four-cell address blocks at `43446`, `43494`,
`43574`, `43638`, `43686` and `43766`. No source auxiliary, numeric bound,
acceptance predicate or desired evaluator output is supplied as an extra
premise to the final typed-validity endpoints.

The final 174 numeric equations occupy globals `20320..20493`. Twenty-six
modules derive all initial/asset/scale/counter bindings, nonmint zeros,
decimal and epoch equations, time and retirement low/high parts, thirty
three-limb product equations, collateral differences, the final borrow and
all carry cells. The source supplies the exact natural auxiliaries; no
accepted-program or desired field equation is an extra endpoint premise.
The 198 coefficient lemmas follow the actual expression DAG.

Together these indexed results discharge all 20,605 actual raw CSR attempts
and all 830 nonlinear roots in all 64 lanes. The complete composition in
`SmallWoodV8Smz9SourcePackedConstruction.lean` now derives actual CSR
coefficient/Option-interpreter execution, all-lane nonlinear acceptance and
full packed acceptance on the same fixed constructor from typed validity.
These are raw attempt counts, not a fixed count of
public-dependent normalized emitted rows. Rust refinement, cryptographic
security and production authorization remain separate.

## Remaining-count sampler batches

`SmallWoodV8Smz9RuntimeBatchBridge` models each successful refill with exactly
the remaining number of raw U64 candidates. It subtracts the actual accepted
count, permits unchanged-width all-reject rounds, and forbids zero-width or
post-completion rounds. A complete final batch must accept every candidate,
so its last word is exactly the final required acceptance.

The proof constructs a bijection between these completed batch schedules and
the existing first-accept trace vectors. Both inverse constructions and
uniqueness are proved; the batch partition is not an input assumption. The
bijection preserves the full ordered raw list, accepted outputs, raw length,
any fixed serialization and the natural requested-byte total of eight times
the raw length.

`SmallWoodV8Smz9RuntimeBatchLaw` transports the existing normalized ideal
first-accept law through this bijection. A completed schedule consuming
`L` raw words has mass `(2^64)^(-L)`, including every rejected candidate.
The scanner-defined output vector has exactly the uniform field-vector law,
with point mass `p^(-n)`. The generic allocation theorem transports this
same law into downstream randomness layouts. Six kernel-checked boundary
examples in `SmallWoodV8Smz9RuntimeBatchBoundaries` reject incorrect widths
and post-acceptance tails while retaining valid rejection rounds.

This is a finite ideal-trace model, not the real provider law conditioned
on arbitrary success. Errors, failed fills, panic, cancellation, allocation,
machine-size overflow, concrete little-endian decoding, OS entropy and
concurrent allocation still require separate execution or probability
arguments. These files do not prove a finite-refill tail bound or identify
an actual infinite-stream execution with the normalized model.

## Evidence and remaining work

The isolated batch check freshly compiled the two original runtime-law
modules and three new modules, with 22 exact unique axiom-root checks and
five negative evidence-parser controls. Its retained receipt SHA-256 is
`adc0880ffc181c43c5549418e2d7b8458d4cd1c773f14125e453dbd95581947e`.
That check pins actual direct imports, not a fresh transitive build of every
external library. Hash and dense components also passed direct strict
Lean 4.32.2 checks and source reviews before integration. At 2026-09-08
05:50 UTC, `LEAN_NUM_THREADS=1 bash scripts/check_formal_crypto.sh` passed
2,953 build jobs and all 803 credited declarations using only `propext`,
`Classical.choice`, and `Quot.sound`. The three proof-wire vectors and all
48 generated relation modules were unchanged. This increment adds eight
modules and 58 designated roots. The complete gate log has SHA-256
`1b87ed225f90d70341a0c0a550f074572e783dd89d248b294fab7151b7789a77`.

The subsequent forward-hash/prefix increment adds eight modules and 49
designated roots: 10 hash, 21 typed-prefix, 11 CSR-coefficient/residual and
7 concrete prefix/dense-composition roots. The frozen first-prefix receipt
is `ca3084c6cb74679cf14fe54193f3f326dc4d94b02cee25e0cfc3a8c326e8ccf3`;
the dense composition receipt is
`45946647d21670ab4d8b9160fa65d7e72d5d5d713ba60877eee7b2e4c775d098`.
Each source was strictly checked before integration. Independent source
reviews found no material issue in the forward-hash chain or final typed
prefix. These checks pin direct imports, not a hermetically rebuilt external
dependency closure. At 2026-09-08 06:15 UTC, the complete integrated gate
passed all 2,961 build jobs and all 852 designated axiom roots. The three
proof-wire vectors and all 48 generated relation modules were unchanged.
The new gate log SHA-256 is
`8a8baa5b4ad93556b3d7fb10b645612c8527b71116e63e72f7887bb77fce42c9`.
Original source/receipts and this log are retained locally under
`.agent/artifacts/smallwood-poseidon2-v8/formal-forward-852-8a8baa5b4ad93556`.

The typed-schedule, authorization, inline, full-prefix and stable-tail
increment adds 16 modules and 153 designated roots. At the 2026-09-08
06:58 UTC checkpoint, the complete central gate passes 2,977 build jobs and
all 1,005 exact credited roots against the same three-axiom allowlist.
All three proof-wire vectors and all 48 generated relation modules
(2,266,857 source bytes) remain unchanged. The full gate log SHA-256 is
`6429f42ae2790f52e06135ba58967e4a5f6cf602edd312bab75396b28a82e995`.
Original source/checker/receipt evidence and that log are retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1005-6429f42ae2790f52`.
The evidence retains the same non-hermetic direct-import boundary.

At the 2026-09-08 07:33 UTC checkpoint, the next 18 integrated modules
and 95 exact roots pass the full central gate: 2,995 build jobs and 1,100
credited declarations on the unchanged three-axiom allowlist. All three
wire vectors and 48 generated relation files (2,266,857 source bytes) match.
This includes the remaining stable canonicality, checked-subtraction helper,
four actual authorization digests, full typed candidate and complete raw
replication family. The log SHA-256 is
`abd82c808ea7383809e4f22c6251495144ded6f1ae3532bff239e7673a305260`.
The original reviewed sources/checkers/receipts and log are retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1100-abd82c808ea73838`.
These direct-import receipts are not a hermetic rebuild claim.

At 2026-09-08 07:50 UTC, the next ten source modules and 63 designated
roots passed the complete central gate: 3,005 build jobs and all 1,163
declarations on the same kernel-axiom allowlist. The three wire vectors
and 48 generated relation files remained unchanged. This increment covers
the 1,920 Merkle CSR attempts and 26 stable roots described above. The
gate log SHA-256 is
`77e97c320cbf1f2fb0335a9622b61eb7c451f22b00ae97576b124648465a3a30`.
Original source/checker/receipt evidence and the log are retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1163-77e97c320cbf1f2f`.

The next 23 reviewed modules add 121 designated roots for policy frames,
inline orientation/policy binding, multiplication, early roots and balance.
At 2026-09-08 08:44 UTC the full gate passes 3,028 jobs and all 1,284
designated declarations on the unchanged allowlist; all wire vectors and
48 generated relation files remain unchanged. The full log SHA-256 is
`43a14c88c4badaf9f3c5a2b5488bec9fc8df9f88d25178c92a225a9ba445d218`. Original
source/checker/negative-control evidence and both intermediate gate logs
are retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1284-43a14c88c4badaf9`.
Forward coverage at that earlier snapshot is 17,552 actual CSR attempts
and 488 nonlinear roots.

At 2026-09-08 09:09 UTC the twelve-module increment passes the complete
3,040-job gate with all 1,356 designated roots on the same axiom allowlist.
All three wire vectors and 48 generated relation files remain unchanged.
The full log SHA-256 is
`260c85fa1d83555ccf8ff8e18ffc44e19ee83e1e4718446ccfaa4b659a852fba`.
Original sources, checkers, negative controls and receipts are retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1356-260c85fa1d83555c`.
Independent reviews compare the actual generated records and coefficient
DAG, not only descriptive labels. The new coverage is 18,496 CSR attempts
and 633 nonlinear roots at that checkpoint.

The next integrated check passes 3,066 jobs and all 1,472 designated
declarations, again with unchanged three wire vectors and 48 generated
relation files. It adds 116 audited declarations across 26 modules. The log
SHA-256 is `c2781561bd8f3b2bdc0a51f94ff025cb123c46f92fac7d292a4e6b585b38484b`.
The 118 original source/checker/control/receipt/log files are retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1472-c2781561bd8f3b2b`,
with a complete byte-identical copy manifest. Coverage at that checkpoint is 18,935 CSR
attempts and 733 nonlinear roots. The separate 210 role-binding draft was not
counted at that checkpoint.

The next seven current-qualified modules derive all 210 actual role-CSR
attempts `19344..19553`, including all 640 terms and 168 explicit zero
coefficients, on the same full typed source candidate. The full gate passes
3,073 jobs and all 1,502 declarations; log SHA-256
`2d0ea4a4b323af3f2062f8725302611f7c0451e087d6962bfdff889f9416110b`.
The raw qualification checks seven modules, 30 exact roots, six mathematical
negative controls and strict parser controls. Evidence is retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1502-cfa3d0d25b27111a`.
Coverage at that checkpoint is 19,145/20,605 CSR attempts and 733/830
nonlinear roots; 1,460 CSR attempts and 97 nonlinear roots remain there.

The subsequent strict qualifications close the final 97 nonlinear roots,
complete the actual nonlinear interpreter endpoint and add 220 CSR attempts
(28 digest copies and 192 inline-policy/padding entries). The first combined
1,752-declaration gate builds all 3,086 jobs and regenerates identical wire
vectors, but its audit rejects a declaration-list comment heading. That run
is failed evidence, not a completed gate. Removing the heading preserves all
theorem names. The corrected 1,767-declaration gate passes 3,087 jobs and all
declaration audits with unchanged wire vectors. Its log SHA-256 is
`cb6b91b97da5517d9c7d6358e27120d5251dca9af7ff7560de92f86c6a9f1009`.
All 268 evidence payloads (15,391,024 bytes), including the failed earlier
attempts, are retained byte-identically under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1767-cb6b91b97da5517d`.
Four strict receipts qualify all 14 migrated source modules and 265 added
declarations. Coverage at that checkpoint is 19,365/20,605 CSR attempts and all
830 nonlinear roots; the complete actual nonlinear interpreter endpoint is
included, not only separate field-root equations.

The four subsequent strict receipts qualify eight modules and 95 added
declarations. The dense-103 receipt is
`57511cee7598b918da929f4bb354789812cf01f215fa5a9170efaa525916b9ab`;
base-111 is `2f8a0beaee3fa6af9b52d4f002ec7467ccbe970026ec4fe6109089a64e696f78`;
authorization-128 is
`8a923150d3f37a4ea8002bcd25864b158676b3c06f51d800b3fa36a57a911241`;
key-12 is `74f77513e226f9cb5ba5ea2f33d53568238168887fd6e540cab2ac4a486a22e1`.
They reject 40 mathematical negatives and 36 parser negatives and check
all source/tool/import pins before and after every compiler invocation.
Independent postflight verifies all frozen inputs, fresh outputs and logs.
Peak child memory is 2,555,904,000 bytes. Parent and separate read-only
reviews check source binding and premise scope. Failed drafts and the
first key-control namespace error remain uncredited evidence. Exact
import-only migration adds the 95 roots to the declaration list, for
1,862 total. The combined gate passes all 3,095 jobs, exact declaration
audits and three byte-identical wire vectors. Log SHA-256 is
`1191e073689038d1343296066b47439849a8e79ca6edc04a1d6ed01ce3495a9f`.
All 291 payload files (29,509,819 bytes) are retained under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1862-1191e073689038d1`;
copy-manifest SHA-256 is
`8deeea715965e135ecc54f3e68e5e5a03d9711e08c4e82948bc111f48b0e2552`.
This is an exact evidence archive, not a portable hermetic replay or a
new production-binary source freeze.

The next three strict receipts qualify 21 modules and 134 declarations.
The note-216 receipt is
`8d8a061eac32de107ee5c89393b7293f61cec2567f6d8d511abda34893ea0718`;
nullifier-32 is
`125bbc500feac3578b6e4deb540c129dc932dcbaed5e4a92ddab92c3201caece`;
public-digest-42 is
`b999fa08c74de01e055a19fb2b5205981f561a1c65e3d119c92e4991f8f72ec9`.
All 44 mathematical negatives and 27 parser negatives are rejected.
Independent pre-integration postflight verifies every frozen input, all
24 fresh outputs and 68 logs. Peak child RSS is 2,889,580,544 bytes.
Separate source review verifies the source/typed/public direction and
exact index coverage. Import-only migration adds the 134 declarations,
bringing the complete inventory to 1,996. The full integration gate passes
all 3,116 jobs, exact kernel axiom audits and unchanged-vector checks.
Gate-log SHA-256 is
`ed9d9e03b53fb45fbb54d306b0cb64fa53fa684713f6fb6f0e9a42df55ef7c31`.
The exact 558-file, 103,676,117-byte evidence archive is
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-1996-ed9d9e03b53fb45f`;
copy-manifest SHA-256 is
`e20ed7a6fb6e987dc112839df9b64d96c43d934ad6000c4e90164efea4272644`.
This does not change the earlier runtime binary freeze or constitute
a portable hermetic replay or production authorization.

The next 332-equation batch has four independent strict receipts. In order
configuration-112, path-128, leaf/issuer-64 and public-output-28, their SHA-256
values are `68105e401dda3756e9fd9885c0b95e319c4df2531a515c1e83c6568b987568fa`,
`cb0f97422c44ed4d74a1e85182af4fd5d0daf3ba5880364b3352820922c42c88`,
`e237bf09dfcdbc0ffb767e5a141d06e3c4f50926b461a15de40344e8e99fbd25`,
and `8733a3d74d800043571cc4f46661f42655f6bd6cad6829fb7a2fb0ed7a9daed2`.
They reject 42 mathematical and 36 parser negatives. Independent
pre-migration postflight verifies all 3,768 input-pin occurrences, 27 fresh
outputs and 69 logs, with peak child RSS 2,488,270,848 bytes. Source review
checks the forward bindings, gating and exact indexed coverage. Import-only
migration adds 15 modules and 87 unique declarations, bringing the inventory
to 2,083; migration SHA-256 is
`24ec2dadf121415fa6df8d2a718e1ba79243cb3e56a26ee1688727586add1300`.
The combined repository gate passes all 3,131 jobs, all 2,083 kernel axiom
audits and unchanged-vector checks. Full-gate log SHA-256 is
`a08ea36246cb35e5b1227905d880c61d3c467d79cf58a82ea7e8e99ac2022316`.
The exact 533-file, 88,070,836-byte evidence archive is
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-2083-a08ea36246cb35e5`;
copy-manifest SHA-256 is
`613689183d124209fe52abf25145c62016919fac0ce56e54c9850554d1a9062d`.
All copied sizes and hashes pass independent readback. This increment
does not relabel the existing runtime freeze or grant production authority.

The next 90 range equations are strict-qualified in one ten-module packet.
The receipt SHA-256 is
`1a60e85b14c56e309f0a5a9a6a40dfe7250be66caaaaf6f451de04afe8d1e51e`.
All 24 mathematical negatives and nine parser negatives are rejected.
Independent pre-migration postflight verifies 983 frozen input pins, 11
fresh outputs and 35 logs; peak child RSS is 2,413,821,952 bytes. Source
review checks the forward bounds, top-bit and digit bindings, coefficient
signs and exact indexed coverage. Import-only migration adds 46 declarations
for a total of 2,129; migration SHA-256 is
`279e97232e635ddce6df6122cefdf65dc09e63f5df301f32ec10b79bcb677c04`.
The combined gate passes all 3,141 jobs, every declaration audit and the
unchanged-vector checks. Full-gate log SHA-256 is
`672254cd2af528ad5621b22cf1ff4cfa8e11666e2c23052164023fcc9576a372`.
The exact 222-file, 38,418,652-byte evidence archive is
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-2129-672254cd2af528ad`;
copy-manifest SHA-256 is
`688c4be9357a1b9301a182fb7d8f1393488c36bc20683cf2d9bff649e27116f1`.
All copied sizes, hashes and the complete payload set pass independent
readback. The rejected initial padding mapping and failed development runs
remain uncredited evidence. A whole-table finite lookup exceeded the existing
compiler cap; the qualified proof uses bounded chunk membership without
changing the limits or the statement proved.

The final numeric packet strictly qualifies all 174 remaining equations,
with 354 audited declarations in 26 modules. Its receipt SHA-256 is
`92f273e2a7c5e6216bc6f7ff4bcf9d4f908ba51406b2b6ff2e41236c4f5e9de5`.
All 24 mathematical and nine parser negatives reject. Independent postflight
checks 1,015 input pins, 27 fresh outputs and 51 logs; peak child RSS is
2,390,081,536 bytes. Import-only migration SHA-256 is
`4074b53b0aafd5cc61c04a1ed33b004a96b33ca4013d39dd312f215e38d1c370`.
The combined gate passes all 3,167 jobs, every one of the 2,483 declaration
audits and unchanged-vector checks. Full-gate log SHA-256 is
`f7e3b6b83e6f890e36c6df33e0fff6407c751545709be0f862e682e950a0510a`.
The exact 504-file, 50,934,511-byte evidence archive is
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-2483-f7e3b6b83e6f890e`;
copy-manifest SHA-256 is
`b52d2d7e1390aebe83d5db79de56105bfdd8ab0483514598ffd743a3cc4617c6`.
Independent exact-set, size and hash readback passes. Failed drafts and
development checks remain uncredited. The complete disjoint source index
accounting has SHA-256
`48ea5e730685d984218d9b25e59e096295cb7d44e183105454350950b3d3397a`.

The next seven modules compose the complete actual CSR table. The early,
middle and numeric dispatchers cover every index once; note-preimage ordering
is transported into actual global coordinates. Membership-to-index conversion
feeds the exact residual equations into a canonical coefficient/interpreter
construction, without assuming interpreter success. The endpoint combines
that result with all 64 nonlinear lanes and supplies
`CanonicalPublicPackedDomain` for `fullTypedSourceCandidate statement witness`
from `ExactV8RelationSemanticValid statement witness` alone.

Two typed privacy modules derive the request's actual retained count and
public equality, then instantiate the existing conditional ideal single-request
bound. The common public record is constructed explicitly; a bare reflexivity
elaboration attempted to compare large private constructors and exhausted the
unchanged memory cap. The explicit record proof and split public-only helpers
preserve the proposition. Binding contents remain caller-supplied public
parameters, not a proved serialization of the actual binding bytes.

Fresh qualification rebuilds all nine modules and audits exactly 28 theorem
roots. All 18 mathematical/projection negatives and nine parser negatives
reject. Independent postflight checks all 1,044 frozen pins, ten fresh
outputs and 28 logs; peak child RSS is 2,785,918,976 bytes. Receipt SHA-256 is
`dc61f9b41429cefed82f0144c1b4ed61ae17485f0b0f5556457cae6afacf277a`;
exact import-only migration SHA-256 is
`be3be42b399fa4cfc27ab36912529685ab4375125b156117a7d80f06871f4d1a`.
Independent read-only review finds no hidden admission or extracted-witness
premise. The combined gate passes all 3,176 jobs, all 2,511 declaration audits
and unchanged wire-vector checks in 738.07 seconds. Its log SHA-256 is
`ac5e02735422fa2a0936179072a21c8b042f2d0f1ff950f81576c96047596076`.
The whole-package run peaks at 3,259,678,720 bytes (3.04 GiB); it is not the
separate M2800/<3 GiB single-module qualification receipt above.
Retain 272 exact payloads, totaling 20,468,422 bytes, under
`.agent/artifacts/smallwood-poseidon2-v8/formal-source-2511-ac5e02735422fa2a`.
Copy-manifest SHA-256 is
`a212de049d4d1f1f6f47547b006fe8e5666e89550c847a5f9c4aecde46a97714`;
independent exact-set, size and hash verification passes for every payload.

Actual Rust success, output equality, decoding
roundtrip and production binary refinement remain additional obligations.
The universal weighted soundness bound is also still open. No runtime,
wire format, primitive, dependency pin or production capability changes here.

The corrected source freeze `2c14119da9a0705c` includes the earlier
1,502-declaration formal snapshot, not these later source additions,
and has its own fresh proof pair, four cross-verifications, matching chain
reports and completed in-process and actual-socket local lifecycle receipts.
The earlier `cee3cb81` artifacts remain evidence for their original source
inventory, without relabeling or replacing either receipt. Neither generation
nor local carrier success closes the remaining security endpoints.
