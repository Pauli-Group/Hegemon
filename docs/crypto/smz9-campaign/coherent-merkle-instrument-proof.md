# Connect coherent SMZ9 extraction to the physical CMS kernel

This is a living bounded proof ExecPlan, maintained under `.agent/PLANS.md`.
It owns only `formal/crypto/HegemonCrypto/SmallWoodV8Smz9CoherentMerkleInstrument.lean`
and this note. It does not authorize a production route, modify proof bytes,
or change the security-history budget.

## Purpose / Big Picture

Make the framed-graph extractor into a genuine reversible quantum operation,
and derive a quantitative statement about the existing compressed-oracle
matrix rather than accepting a desired norm estimate as an assumption.
A compressed database here is a quantum register whose basis values are finite
maps. It is never read out as a classical query log in these constructions.

The currently implemented endpoint is deliberately narrower than the final
security endpoint: an arbitrary fixed Boolean observation of the full source
extraction has a proved reflection/query squared commutator bound. The faithful
multi-answer extraction unitary is constructed separately; its full commutator
lift still needs the generalized partition argument.

## Progress

- [x] (2026-09-07 17:03 UTC) Inspect the frozen Geometry module and actual CMS kernel,
  local-operator proof, finite database, reachable-support and phase-system APIs.
- [x] (2026-09-07 17:12 UTC) Implement explicit byte/bit conversion, complete Walsh
  phases, finite raw-database extraction, and reversible source-answer encoding.
- [x] (2026-09-07 17:16 UTC) Implement source Boolean instability, concrete crossing,
  reflection commutator and strict-support removal of the query cutoffs.
- [x] (2026-09-07 17:23 UTC) Strict Lean check and seven-theorem dependency audit
  pass; only `propext`, `Classical.choice`, and `Quot.sound` occur.
- [x] (2026-09-07 17:24 UTC) Diagnostic print commands removed; final clean-source
  strict check exits zero with no output. Source and note whitespace checks pass.
- [ ] Mechanize the multi-output partition commutator, including arbitrary
  superposed target registers, without a label-count factor.

## Context and Orientation

`SmallWoodV8Smz9CoherentMerkleGeometry.lean` parses literal SMZ9-framed raw
preimages. It follows the root-binding and PIOP wrappers and the depth-23
Merkle tree, retaining complete selected wrapper payloads. Its deterministic
least-preimage selection changes only when a new digest hits a target or an
old parsed child. At most two child digests come from each recorded input.
For at most `t` targets and fewer than `t` records, the probability of any
extraction-label change under a fresh uniform raw digest is at most
`I = 3t / 2^512`.

`CmsCompressedOracle.queryState` is the actual finite complex matrix with
retained, erased and replaced database entries. Its output group is an
additive group, and its phase register must enumerate all additive characters.
`CmsFullOperatorProof` proves `||P O (1-P) psi||^2 <= 6 I ||psi||^2` by explicit
matrix/fiber calculations. `CmsCompressedOracleUnitary` proves that this kernel
preserves norm on the strict reachable pre-query support; the cap is not a
claim that the unrestricted capped matrix is globally unitary.

## Plan of Work and Milestones

The first milestone gives the physical registers their exact source meaning.
`byteBits` uses the explicit base-two digit equivalence; `rawDigestBits`
flattens byte index and little-endian bit index to position `8*byte+bit`.
The CMS output group is `DigestRegister = Fin 512 -> ZMod 2`, so addition is
bitwise XOR, not bytewise modular addition or a cyclic `ZMod(2^512)` group.
`digestCharacter` constructs the Walsh product pairing. Evaluation at a
single set bit proves character injectivity; equal phase and output dimensions
then give `digestCompletePhaseSystem` without a cryptographic premise.

The second milestone makes the extractor reversible. `rawRecords` contains
all and only recorded raw-byte pairs; its cardinality is at most the database
size, and fresh insertion commutes with its conversion to Geometry records.
`sourceLabel` is exactly the old full extraction trace. Its finite range is
encoded injectively as a one-hot XOR vector. `source_one_hot_is_faithful`
proves that equal encodings imply equal full extraction traces.
`sourceExtractionEquiv` updates only the answer register and has an explicit
inverse. Its complex-linear extension preserves the complete squared Hilbert
norm with arbitrary targets and residual workspace. The one-hot representation
is a finite mathematical encoding, not an efficient circuit or storage claim;
no enormous table is evaluated or materialized by the Lean check.

The third milestone connects classical counting to the physical query.
Every fixed Boolean test of `sourceLabel` has two-sided CMS instability at
most `3t/2^512`, proved by an injective image of successful answers into the
Geometry changed-digest set. This yields the actual projected-query bound
`18t/2^512` times the input squared norm. `partitionReflection` multiplies
amplitudes by minus one on the selected partition cell. Its exact matrix
commutator is minus two times the difference of the two crossing operators.
Their target supports are disjoint. Applying the homogeneous `6I` estimate
twice proves the conservative bound `48I`, hence `144t/2^512` for source
extraction observations. `reflection_commutator_is_actual_query` removes
both cutoff projections when the input database support is bounded by an
explicit `b < t`. Thus the endpoint names the actual `queryState`, not just
a generic operator supplied with its desired bound.

## Surprises & Discoveries

The existing complete phase-system constructor is cyclic. The group of
512 XOR bits is not additively equivalent to a cyclic group of order `2^512`.
The new product-character construction is necessary to avoid that mismatch.

The CMS theorem accepts one property of the database, fixed across workspace
blocks. The general extraction instrument needs a workspace-dependent family
of properties, followed by a finite sign-averaging argument. Applying the
fixed-property result to each extraction label and summing would introduce an
unacceptable label-count factor; no such step is used here.

## Decision Log

Use an explicit one-hot finite encoding for the faithful full trace unitary.
This establishes existence and reversibility without pretending that the
large symbolic answer register gives an efficient source extractor.

Keep the proven binary reflection endpoint separate from the full
multi-answer-register theorem. The primary generalized result is Theorem 5.4
and Corollary 5.6 of Chiesa, Di, Hu and Zheng,
[*How to Prove Post-Quantum Security for Succinct Non-Interactive Reductions*](https://eprint.iacr.org/2025/2166.pdf),
March 2, 2026 revision. It bounds the squared commutator of a unitary controlled
by a database partition by `80 I`, provided each controlled unitary commutes
with the oracle. Section 5.1 was re-inspected directly in the retained primary
PDF text in this lane. Applying this result to the constructed complete
extraction instrument remains an explicit external mathematical step, not a
Lean axiom, structure field, or proved conclusion in this module.

The proposed full-partition follow-up must extend the homogeneous CMS proof
to properties depending on the fixed workspace block and check an explicit
label-dephasing argument. The earlier proposed answer-register argument was
incorrect: `E Q E^-1 - Q` need not have zero diagonal answer blocks. That
unproved shortcut is withdrawn. The binary theorems do not use it. No constant
for the corrected full-partition route is credited until its averaging,
operator identities and workspace-family proofs pass.

At the external-paper level the numerical substitution is
`80 * (3t/2^512) = 240t/2^512`, before an experiment adds its separate `t+1`
budget convention. This is not the conclusion of the Lean binary-reflection
theorem, and it does not discharge the identification of the paper's operator
with the fully compiled source-sized vector oracle.

## Concrete Steps and Validation

Use the existing warm Lean environment from `formal/crypto`:

    lake env lean -DwarningAsError=true -o /tmp/SmallWoodV8Smz9CoherentMerkleInstrument.olean HegemonCrypto/SmallWoodV8Smz9CoherentMerkleInstrument.lean

Success is exit zero with no diagnostics. The strict audited run completed
with exit zero at 17:23 UTC. Its seven dependency reports contain only
`propext`, `Classical.choice`, and `Quot.sound`. The subsequent clean-source run
also exits zero with no output. Its temporary object occupies 968 KiB. Inspect dependencies with `#print axioms` for
the source faithfulness, norm, instability and actual-query endpoint theorems,
then remove those diagnostic commands and repeat the strict check. No `sorry`,
added axiom, `native_decide`, unsafe definition or disabled linter is permitted.

## Idempotence and Recovery

Checks produce one small temporary object, never a materialized oracle table.
The central import cache remains root-coordinator-owned. The source files are
additive and can be rechecked without launching a node, rebuilding Rust,
changing retained artifacts, or editing existing modules. No files are deleted.

## Interfaces and Dependencies

The source theorem quantifies a finite raw-input universe through an injective
`Key -> RawInput` embedding, a fixed target list, a fixed Boolean observation,
and an arbitrary finite private workspace. Both digest and phase registers
are concrete 512-bit XOR vectors. Its support premise is an explicit bound on
the actual input state's database basis support, not a query-success premise.

The separate raw-counter compiler is generic in vector width. Under the
current 20,605-row CSR upper bound it needs up to 12,883 SHA-512 blocks in one
vector answer, not 523. This module does not silently substitute that vector for one
512-bit raw answer. A future vector-CMS adaptation must prove that the selected
counter-zero digest has the uniform 512-bit marginal and transport the source
parser through that projection. The `t=2Q` compiler bookkeeping and that
vector-output physical instantiation are not already composed here.

## Outcomes & Retrospective

The strict audited source passes. This bounded lane supplies a
source-faithful reversible unitary and a non-assumed physical Boolean
commutator bound. The generic squared-norm theorem applies to the exact source
permutation; a redundant fully expanded one-hot source corollary was removed
after its concrete finite-instance elaboration became expensive. This does
not affect the proved source answer faithfulness or generic unitary theorem.
Remaining security obligations include the full partition
lift, efficient reversible extraction, exact accepted-opening consistency and
wrapper-context checks, current counter-vector chronology, round-by-round
decoder binding, experiment composition and the independent release gates.
Neither this theorem nor the referenced generalized theorem authorizes SMZ9.

Revision note: 2026-09-07, initial source/physics construction and explicit
separation of the mechanically proved binary endpoint from the full extraction
partition theorem.

Revision note: 2026-09-07 17:23 UTC, strict dependency audit passed. Retain the
explicit large-register and vector-oracle limitations and remove diagnostic
print commands before the final clean-source check.

Revision note: 2026-09-07 17:24 UTC, final clean-source strict check passed;
both owned files are frozen for coordinator review.
