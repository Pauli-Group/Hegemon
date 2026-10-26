# RP05 adaptive context and extraction obligation

Status: H2 remains open. The four maintained public roots retain their exact
statements. The additions below are supplemental theorems, not a replacement
knowledge-soundness endpoint or launch approval.

`Rp05.soundness` fixes namespace, statement, pending flag and nonce before the
producer runs, assumes that no satisfying packed witness exists, and bounds
acceptance. The producer can make oracle-dependent reads and return a parsed
proof-field view. The endpoint does not select its public context adaptively,
and it does not return an efficient extractor for satisfiable statements.
Authorization and conservation also fix their history-stage list.

## Checked progress

`formal/rp05/shared/SmzaRp05ContextExtractionAccounting.lean` reuses the existing
accepted full-extraction-failure endpoint to derive a fixed-context failure
bound below `2^-130`, without a `noPackedWitness` premise or a supplied
probability-bound premise. This retains the existing existential X-view/source
selector; it is not an efficient extractor theorem.

The module defines `ProducedContext` and `contextProducingVerifierProgram`, in
which the producer's oracle-dependent result supplies the context and proof.
It proves their exact executable evaluation equation. It also proves a
finite-family sum bound and common-outcome adaptive selection accounting,
including relation-invalid extracted witnesses. A sharp diagonal example shows
why conditioning cannot simply discard the number-of-contexts loss. These
generic selection lemmas do not identify the actual physical failure mass with
the family of fixed-context experiments. Varying only the 32-bit nonce would
already lose 32 bits under this naive union bound.

`formal/rp05/shared/SmzaRp05ContextPhysicalBind.lean` proves:

- every accepted bind branch decomposes into the producer and continuation,
  with the exact concatenated answer log and physical state;
- the context-output verifier starts in the producer's actual unnormalized
  state, using one encoder for the whole program;
- accepted branches replay on the whole program's finite grouped key universe,
  retaining the continuation's nonchallenge calls in that same database.

There is no oracle reset, conditional independence, or fresh incoming-unit
assumption at the split. These proofs close the local physical bind/replay
transport. They do not supply the missing extraction-event inclusion or bound.

`formal/rp05/shared/SmzaRp05ContextAmbientDecoder.lean` additionally constructs
the exact same-stage collision-or-decoder outcome from that retained trace on
the entire context-producing program's keyspace. Its `ParsedContext` producer
carries public-statement parsing evidence and keeps namespace fixed. The
construction preserves the actual transcript, execution and PCS stages; it
does not assume extraction coverage or the desired probability bound. The
unguarded producer still needs a parsing connection, and full/failure X-view
measurability plus role/advice-event mass accounting remain open.

`formal/rp05/shared/SmzaRp05ContextAmbientCoverage.lean` derives an ambient
full/failure X-view classification: an actual accepted branch with database
claims gives a filtered collision, the exact designated full-source extraction
with a typed accepted witness, or an existing role failure. The selectors retain
the completion database, produced context, producer-success equation and actual
stages. They quantify database completions; classification alone does not
establish the adaptive role/advice support or its probability bound.

`formal/rp05/shared/SmzaRp05ContextAmbientSupport.lean` transports that role
evidence to the actual merged fixed/active database of a nonzero selected-state
basis. Recognized challenge claims and selected support supply full branch
claims. Those claims force the completing and actual databases to replay the
same producer context, even if it depended on challenge answers. Equal
nonchallenge views preserve erased records and transport the decoder and role
failure. This uses no assumed context measurability, oracle independence,
density bound or union over contexts. Missing recognized claims remain a
separate arm. The concrete role evidence still needs the role/advice-event bridge.

`formal/rp05/shared/SmzaRp05ContextAmbientMatrixEvent.lean` closes the DECS
matrix advice-event support bridge for the entire context-producing program.
It derives actual nonleaf/filtered traces, the stored DECS-vector binding and
the matrix role event. Nonzero selected-state support then implies the existing
`currentAdviceEventSpec` or missing recognized challenge claims. This reuses the
existing event definition without a new coverage, density or independence
premise. The next two modules close the corresponding DECS sample bridge; the PIOP module below closes both remaining role-support bridges.

`SmzaRp05ContextAmbientSampleSupport.lean` derives the actual sample-output
binding and fixed earlier-cell readback on the ambient database.
`SmzaRp05ContextAmbientSampleEvent.lean` then derives the DECS sample advice
event or missing recognized claims from actual nonzero selected-state support.
Both DECS bridges keep the produced context and earlier advice on the same
physical outcome, without a new coverage or density premise.

`SmzaRp05ContextAmbientPiop.lean` derives actual PIOP record/output binding,
fixed earlier-advice readback, and the matrix/opening role events. Its
`PiopRole`-indexed support theorem covers both PIOP roles on the same ambient
program. Together with the two DECS modules, all four support bridges now
derive the existing advice event or missing recognized claims. The positive
block-cap premises are structural; no desired coverage or probability bound
is assumed. The following modules provide joint mass accounting; the efficient extractor remains required.

`SmzaRp05ContextAmbientFourRole.lean` joins all four support bridges.
`SmzaRp05ContextAmbientFailureMass.lean` bounds accepted full-extraction
failure mass by one global erased-record collision, the four ambient failure
selectors and missing nonchallenge claims. The collision is transported to the
existing collision fibers on the original physical amplitudes. There is no
context-cardinality factor, conditioning reset, or supplied probability bound.
The following module connects this decomposition to the numerical endpoint.

`SmzaRp05ContextAmbientScalarEndpoint.lean` derives scalar accounting and
`SmzaRp05ContextAmbientEndpoint.actual_accepted_full_extraction_failure_mass_below_130_bits`.
This endpoint quantifies an oracle-adaptive `Program ParsedContext`, keeps the
source namespace fixed, assumes a normalized ordinary input, and requires
`queries + readBudget <= cap` and `cap <= 3*2^64`. The actual accepted
full-extraction-failure projection is below `2^-130`. Four-role inclusion,
scalar accounting and the numerical bound are derived internally, without a
`noPackedWitness` premise, context sum, or assumed probability bound. This
closes the adaptive parsed-context **model probability** obligation. The selector
is still an existential full-source predicate, not a costed physical extractor.

## Remaining construction

The checked constructions use one ambient program and its `Key(P)` throughout.
Namespace is source-owned and fixed; the producer selects a successfully parsed
statement, pending flag, nonce and proof view. The decomposition,
four-role support inclusion and numerical bound now apply to the original
joint physical execution. The unguarded proof-view producer still needs the
parsing connection; serialized Rust acceptance is a further boundary.

The required efficient extractor and its query/time overhead must then be
established for the actual security experiment. Serialized Rust acceptance,
adaptive history selection, primitive advantages, and production authorization
remain additional boundaries. Consult the explicit extractor requirements in
`docs/crypto/smz9-campaign/security-contract.md` before claiming H2 resolved.

## Efficient extractor work still required

The recovery path is constructive: the MCA decoder selects sorted support
positions, interpolates, and checks agreement; `packedFromRows` unpacks 43,904
words. The existing successful arm retains this decoder output and packed
acceptance. Nevertheless, `rawRecords` filters `Finset.univ` over key/output
pairs. Bounding the number of resulting records does not bound that enumeration.
An occupied-entry implementation needs an equality/refinement theorem, followed
by indexed or memoized Merkle recovery and an explicit execution-cost theorem.

The current support computation scans all `N = 2^23` positions and grouped
outputs contain 12,872 digest coordinates. Those operations must be charged;
freezing the geometry does not establish polynomial dependence on `log N`.
The reversible extraction equivalence also supplies no circuit-size bound.
Finally, transport packed acceptance to the contract's semantic witness
predicate in the same joint physical extraction experiment, retaining failure
outcomes. These are concrete remaining H2 obligations, not primitive-game
advantages or release authority.

The supplemental registry makes CI compile and audit these new theorem bodies.
It preserves the baseline four-root source manifest. Component compilation and
an axiom audit cannot promote this document's open obligation to completion.
