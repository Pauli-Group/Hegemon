# Constructive honest rows and the exact batch law

These are forward constructions for the unchanged SMZ9 relation and sampler.
They do not fill the complete semantic or Rust-refinement receipts. The
arbitrary accepted-packed-to-typed endpoint already exists; the remaining
reverse direction must construct the actual honest assignment from the typed
witness and derive its acceptance, not assume an accepted packed witness.

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
These 320 field equations are conclusions of the proof. This does not yet
establish the seven raw linear reconstruction constraints: the private
coordinates must also be bound by the complete constructor.

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

The 125 live initial states are legitimate component inputs. Their derivation
from the typed transaction's ordered hash schedule remains due, as does
forward satisfaction of the 332 actual generated hash roots. The fixed hash
kernel predicate is not substituted for those generated roots or for complete
packed acceptance.

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

Continue by constructing the other typed rows and the live hash schedule,
then deriving all 830 nonlinear roots in every lane and all 20,605 raw linear
constraints. This must supply `CanonicalPublicPackedDomain` for a named
concrete constructor. Actual Rust success, output equality, decoding
roundtrip and production binary refinement remain additional obligations.
The universal weighted soundness bound is also still open. No runtime,
wire format, primitive, dependency pin or production capability changes here.

The earlier `cee3cb81` proof pair and complete local carrier receipt remain
valid evidence for their frozen source inventory. These new formal sources
advance that inventory; a later freeze needs new source-bound evidence,
without relabeling the earlier proofs or replacing their receipt.
