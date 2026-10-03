# Coherent counter-vector Merkle extraction

This is the execution record for the bounded counter-vector bridge. Its source
is `formal/crypto/HegemonCrypto/SmallWoodV8Smz9CoherentVectorMerkle.lean`.

## Purpose and result boundary

The preceding coherent partition theorem handled a scalar 512-bit output.
The literal SHA-512 counter compiler instead returns a vector of 512-bit
blocks. Charging the expanded raw-record count would introduce an unnecessary
factor equal to the counter cap. Dividing a scalar collision set by the
cardinality of the entire vector output would be unsound in the other direction.

The bridge uses the entire counter-vector XOR group and its full product Walsh
phase system. It projects each recorded logical key to one source-relevant raw
record, proves that the complete source extraction is unchanged by that
projection, and counts the exact marginal of the selected coordinate. The
checked endpoint is

`normSquared (E (Q psi) - Q (E psi)) <= (576 * t / 2^512) * normSquared psi`.

Here `Q` is the actual CMS query for the entire vector output; `E` is the
reversible complete-source-answer update; the target, answer and private
workspace may all be entangled. The pre-query support is bounded by `b < t`,
and every target-register basis value specifies at most `t` target digests.

The coefficient is inherited from the local 192-times-instability full
partition proof. It is not the paper's sharper constant. This document does
not claim a full experiment trace-distance result, an efficient extraction
circuit, SHA-512 cryptographic security, or production authorization.

## Progress

- [x] Inspect literal source graph hash roles and the compiler's total raw routing.
- [x] Write exact finite event-counting bijection and full vector Walsh system.
- [x] Write classical source instability and coherent faithful-source endpoint.
- [x] Write expanded-record projection and canonical routing relevance proofs.
- [x] Independent source-only review against the compiler's current total routing.
- [x] Run a warm warning-as-error Lean check in the coordinator-granted slot.
- [x] Audit all eight principal endpoints; only standard foundational axioms occur.

## Exact source and routing contract

The active source's SMZ9 branch of `transcript_xof_digest` invokes
`sha512_commitment_domain_digest` with counter zero. The strict leaf, ordinary
Merkle child hash, root-binding wrapper, and PIOP-input hash all reach that
branch. This observation is limited to these graph roles. The field XOF reads
multiple counter blocks; arbitrary adversary inputs need not be well-framed
and need not end in zero.

The source grammar's `parseFramed` requires the complete profile/role/word
framing, a decoded counter of zero, and no suffix. The new
`parse_framed_counter_roundtrip` preserves any canonical u64 counter in its
statement and proves that only zero can pass that grammar.
`source_next_nonzero_counter` derives rejection for every extraction stage.

Use a finite raw universe and an injective encoding of selected canonical
prefix/counter pairs into that universe. A canonical prefix includes all
profile, role and payload length frames and the full payload. The encoding
has the literal byte equation required by `canonical_routing_source_relevance`.
The selected counter set is `Fin blocks`, with zero present and
`blocks <= 2^64`; there is no fixed 523-block or 12860-block assertion here.

The logical key space is exactly

`Prefix + { raw // raw is outside the selected prefix/counter image }`.

It is the same key space used by
`RawCounterCompiler.fullRawPaddedCoordinate`. Prefix keys select their zero
counter as representative. Complement keys select their own original raw
bytes and use zero only as the padded vector coordinate. In particular, a
complement input's raw bytes are **not** rewritten to have a zero suffix.
Malformed inputs, unselected prefixes and out-of-selected-cap counters remain
in the raw universe, each with its own complement key.

`canonical_representative_address` proves the representative's exact padded
address. `canonical_routing_source_relevance` proves that every raw coordinate
accepted at any source extraction stage has exactly its representative bytes
and the selected zero coordinate. These are deterministic source-framing
facts, not probability assumptions.

## Exact trace preservation

`expandedRawRecords` gives the semantic full raw relation represented by a
compressed vector database. For every raw input, it takes the recorded vector
at the routed logical key and projects the routed counter. It includes the
retained complement without enumerating or materializing a table during the
proof workflow.

`expanded_candidates_eq_projected` proves equality of the source parser's
eligible candidate sets. The proof uses the representative address and the
source-relevance result, in both directions. Thus lexicographic least-preimage
selection is unchanged, including in the presence of unrelated collisions.

`expanded_source_trace_eq_projected` then proves equality of every complete
finite extraction trace, including missingness, budget markers, raw wrapper
bytes and all recursively selected children. The projected relation contains
at most one pair per recorded vector key, so its cardinality is bounded by
the logical CMS database size rather than that size times the counter cap.

This is an equality between the expanded relation of a vector database and
its one-record-per-key projection. It is **not** an asserted equality between
the compressed databases of the original raw-query execution and the compiled
vector-query execution. The compiler separately proves equality of complete
oracle query states under its clean-auxiliary routing circuit.

## Exact finite counting

`coordinateEventEquiv` is an explicit bijection

`{v : Counter -> Output | event (v c)}`

with

`{y : Output | event y} x ({j : Counter | j != c} -> Output)`.

Its cardinality theorem and cancellation of the nonzero residual-vector
cardinality prove `coordinate_event_probability` over rational numbers.
Consequently an event on one selected digest has its ordinary 512-bit
probability even while the complete answer remains a large vector.

`vector_source_step_change_bound` maps successful vector answers into the
coordinate event whose decoded digest belongs to the existing source
`changedOutputs`. Source geometry bounds that digest set by the target
digests plus at most two child digests per old projected record. Existing
records do not change on a repeated query. The bound in both cases is
`3*t / 2^512`; both Boolean-instability directions are derived, not supplied.

## Actual coherent operator

`vectorCharacter` is the product, over every counter, of the proven 512-bit
Walsh character. `vector_character_injective` probes one counter at a time,
and `vectorCompletePhaseSystem` has the full vector dimension. Neither the
output nor its phase labels are collapsed to the selected digest.

`vector_source_actual_full_extraction_bound` instantiates the existing full
answer commutator proof with that system and the new classical counting bound.
`coherent_vector_source_commutator_bound` uses orthogonal target slices without
a target-dimension factor. The final faithful endpoint uses an injective finite
encoding of `VectorLabelRange`, the range of the actual full source trace.
No Boolean observation or externally supplied extracted object replaces it.

The answer-update basis permutation retains the target, phase, query input,
database and private workspace. Its norm preservation is the existing generic
`extraction_preserves_squared_norm` theorem. The finite codec can be huge; an
efficient polynomial-size trace/register implementation remains separate.

## Query compilation and remaining integration

The unchanged raw counter compiler proves the exact uniform raw-table law for
the padded vector oracle and implements a raw XOR query by vector
compute/select/uncompute. It makes two vector-oracle calls and returns the
auxiliary vector register to zero coherently. Its address is exactly the
address used by this bridge's canonical source-relevance theorem.

The present module supplies the source extraction partition and actual full
vector CMS commutator for that address. A caller must still compose the
compiled program with the appropriate CMS oracle realization and chronological
hybrid, account for its strict pre-query support convention, and use the actual
source-derived counter cap. This document does not silently substitute `t=2Q`
inside a final transcript-distance theorem.

## Validation and resource policy

The lane is limited to this Lean module and this execution record. No shared
build cache, runtime code, retained proof artifact, or production document is
modified here. The coordinator imposed a global limit on concurrent Lean
processes; this lane requested a warm slot before any Lean invocation. No raw
table, vector-value universe, or one-hot register is explicitly enumerated.

Strict check, completed on 2026-09-07 at 19:01 UTC in the coordinator-granted
single-process slot:

```sh
cd formal/crypto
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CoherentVectorMerkle.lean
```

Validation status: strict PASS, exit zero with no warnings or errors. No object
file or shared cache was written. A second strict invocation with temporary
`#print axioms` statements passed for these endpoints:

- `coordinate_event_probability`
- `vector_character_injective`
- `vector_source_step_change_bound`
- `coherent_faithful_vector_source_commutator_bound`
- `source_next_nonzero_counter`
- `expanded_source_trace_eq_projected`
- `canonical_routing_source_relevance`
- `canonical_expanded_source_trace_eq_projected`

Every audited declaration depends only on `propext`, `Classical.choice`, and
`Quot.sound`. The audit statements were removed afterward. No linter was
disabled, no proof placeholder was retained, and no protocol file changed.
Verification corrections were restricted to explicit finite decidability
instances, a generic event-cardinality helper, exact cast/byte-frame rewrites,
reserved identifier and section syntax, and unused-instance hygiene.

The compiler owner independently reviewed the routing definitions and found
no mismatch: canonical zero representatives and unchanged complement bytes
use the exact current padded addresses. The review also confirmed that the
bound's `t` counts full-vector queries; the compiler's at-most-`2Q` call count
must remain explicit when composing a raw-`Q` adversary. That review did not
execute Lean; the subsequent strict checks and axiom audit supply that evidence.
