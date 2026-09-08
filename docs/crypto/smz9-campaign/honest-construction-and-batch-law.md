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
separately, without assuming padding conservation. The actual root list,
not its currently misordered descriptive metadata, selects each expression.
Malformed Boolean/path/reserved/ciphertext/asset examples have nonzero
actual roots; nonzero fee/issuance with zero notes and duplicate assets are
separate balance controls, not admitted typed witnesses.

Together these results discharge 17,552 of 20,605 actual raw CSR attempts
and 488 of 830 nonlinear roots in all 64 lanes. Covered root-list positions
are exactly `0..128` and `471..829`; the remaining 342 authorization roots
and 3,053 raw CSR attempts, complete coefficient/interpreter execution and
full packed acceptance remain open.

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
Forward coverage is 17,552 actual CSR attempts and 488 nonlinear roots;
the remaining equations and full security endpoints are still open.

Continue by closing the remaining checked-success obligations and deriving
all 830 nonlinear roots in every lane and all 20,605 raw linear
constraints. This must supply `CanonicalPublicPackedDomain` for a named
concrete constructor. Actual Rust success, output equality, decoding
roundtrip and production binary refinement remain additional obligations.
The universal weighted soundness bound is also still open. No runtime,
wire format, primitive, dependency pin or production capability changes here.

The earlier `cee3cb81` proof pair and complete local carrier receipt remain
valid evidence for their frozen source inventory. These new formal sources
advance that inventory; a later freeze needs new source-bound evidence,
without relabeling the earlier proofs or replacing their receipt.
