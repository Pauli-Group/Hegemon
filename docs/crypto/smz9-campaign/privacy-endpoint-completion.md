# Completing the SMZ9 honest whole-view privacy argument

Date: 2026-09-08. Subject: the repaired HGV8RP03 relation carried by SMZ9,
profile 6, SHA-512
`180fca50376f7573cacedfb5465a0b4d6bf5c61637152035a682d21038016d2239e2f8b50605f36baa635038348dc984197d6df29347e17e1150c24ff737de84`.

The three-stage ideal-QROM lifetime composition is now proved for the actual
modeled source-request program: randomize the honest leaf outputs, randomize
the final PIOP hash output after the joint mask change of coordinates, and
remove unopened leaf programs while retaining every later request. The source
is connected to a directly compiled witness-free public simulator, with no
endpoint-equality or endpoint-distance premise. The universal external
adaptive-reprogramming theorem remains an explicit assumption. This is not
yet a refinement theorem for the actual Rust experiment or a production P7
claim. The historical abort counterexample and the construction details below
explain why the persistent lifetime, not just returned proof bytes, matters.

## Completed ideal source-lifetime endpoint

`SmallWoodV8Smz9SourceLifetimePrivacy.lean` composes the exact source, selected
final-write, hidden-byte, and public-erasure bridges. For the source lifetime's
syntactically charged query index `q` and attempted-request index `r`, write
`a(q,m) = sqrt(q*m) + q*m/2`. The proved bound is

```text
|actualSourceAcceptance - publicSimulatorAcceptance|
  <= (2^23*r)*a(q,2^-512) + r*a(q,p^-3105) + r*4q/2^256.
```

One source request charges at most `16,790,291` queries plus its complete
byte/error continuation. This includes all current leaf writes in the final
hybrid; a write is not a free oracle operation. The first transition selects
at most `2^23*r` leaf events, and the second selects at most `r` full-T events.
The same initial oracle distribution, effective oracle and subnormalized
branch state are preserved through the entire adaptive lifetime, including
all prior and later requests and public failures. All native gates, coherent
queries, honest reads, complete instruments, and random branches are retained.

`SmallWoodV8Smz9SourcePublicSimulator.lean` constructs the simulator directly
from `SourcePublicErasure.PublicLifetime`. Its input contains the **full public
request/control-flow policy**, not just a statement: statement/public values,
statement-binding bytes, salt, retained-row count, native operations and every
possible continuation. It contains no witness, witness-selection function,
packed-domain proof, or oracle-dependent initial advice. The erasure theorem
is derived from the actual request factory. Shared public salt sampling can
be represented by an outer random instruction; no witness-derived salt or
private-dependent public policy is silently treated as shared.

For two admitted witness policies, `PubliclyEquivalent` requires identical
public request data, native actions and public branches for every possible
byte/error result, oracle answer, measurement result and random coin. The
witnesses and their domain proofs may differ at each request. Their common
public erasure yields the same simulator, so the two-witness gap is at most
twice the bound above.

The checked numerical specialization is `q <= 2^65`, `r <= 2^21`: leaf loss
at most `2^-178`, final loss at most `2^-201`, and hidden loss at most
`2^-168`; their sum is at most `2^-167`. The two-witness gap is therefore at
most `2^-166`, strictly below `2^-128`. These are explicit analysis resources,
not an approved deployed lifetime policy or a proved Rust-to-index accounting
map. Concrete SHA-512 construction security, runtime randomness/source and
binary refinement, reverse honest-lowering completeness, universal soundness,
and independent production authorization remain separate requirements.

All new endpoint modules passed strict individual and central builds. On
2026-09-08 at 03:22 UTC, the full integrated gate passed 2,945 build jobs and
audited all 745 credited declarations against the existing three-axiom
allowlist. Generated relation and proof-wire artifacts remain exact. The
campaign status records that full pass separately from individual checks.

## A concrete error in an otherwise plausible splice

`PublicStageGenerator` in
`SmallWoodV8Smz9CurrentPrivacyComposition.lean` chooses the six PIOP points from
the independent leaf labels and the DECS response `D`. It has no `T` argument.
The actual source instead computes `h_piop = H(hash_fpp || T)` and selects the
points from `h_piop`. Therefore leaf-output randomization alone cannot identify
the actual honest execution with `chronologicalRandomizedAcceptance`: it would
silently replace an oracle-dependent PIOP challenge with a challenge selected
before `T`. The required final-input transition is described below.

There is a second, independent discrepancy. The `none` branch of
`generatedSourceObservation` and `executedGeneratedSourceObservation` returns
`failure` directly. In the real randomized-leaf procedure, all leaf programs
have already happened before a later opening-sampler abort. Subsequent oracle
queries observe those writes even though no proof was returned. Returning the
same scalar in two formal branches proves equality of those scalar branches;
it does not prove equality of the complete continued executions.

Here is an exact classical counterexample, which is also a physical quantum
adversary using basis-state queries. Let the oracle domain and codomain both be
bits. Draw `H(0), H(1), x, y` independently and uniformly. Before a request, save
`H(0)`. The request programs `H(x)=y`, then always returns a public error. Query
`H(0)` again and accept exactly when its value changed. The probability is
`Pr[x=0 and y != old H(0)] = 1/4`. If the error branch simply omits its oracle
writes, the probability is zero. Both error strings and their probabilities
are identical. Thus the retained oracle cannot be discarded on error.

The new `SmallWoodV8Smz9HonestWholeViewAbort.lean` candidate counts the four
accepting cases among sixteen equally likely draws. Its constructive repair
uses a `.publicAbort` request phase followed by the entire retained-update
grammar, including later honest and adversarial queries. All current leaves
are hidden on that branch. Applying the existing full-source hidden-patch
theorem and the two-query grammar compiler yields

```
|continued aborted source - continued aborted reference|
    <= hiddenPatchLoss(2q) = 8q / 2^256.
```

The reference restores each hidden current write to the preceding oracle
value; earlier and later request state remains intact. This is a quantitative
repair of the missing branch, not an equality assertion or a change to the
source verifier's abort behavior. The kernel-check status of the new module
is recorded in the verification section below.

## The ordered ideal-QROM reduction

`SmallWoodV8Smz9HonestWholeViewGames.lean` now gives this reduction a physical
finite game language. Its instrument branches are complex-linear Kraus maps
whose squared output norms sum to the input squared norm. The interpreter
sums their subnormalized Born weights and never renormalizes a selected
branch. It allows oracle-independent isometries, coherent queries, charged
classical honest reads, private random draws and fresh-input programming.
Later programs may depend on actual classical measurement and oracle-read
outcomes. The same table and quantum state survive throughout.

The interpreter's final probabilities are derived from its execution;
`run_has_physical_probability` and `game_acceptance_is_probability` prove
their bounds. Query, programming and input-mass bounds recurse over *every*
possible outcome. The source leaf adapter constructs the actual framed
input and proves its mass, exact honest read semantics, and exact randomized
read/update semantics. `measured_adaptive_leaf_game_bound` applies a universal
external GHHM theorem to those computed games. The external premise is the
published theorem's precise uniform-cap statement; it is not a separately
supplied distance assertion for one desired SMZ9 endpoint. The subsequent
source adapters now compile the current modeled request through its literal
post-final byte/error observation. The all-request ideal composition is now
proved as above; concrete Rust refinement remains separate.

Let `N=2^23`, let `p=2^64-2^32+1`, and let `T` bound attempted honest requests,
including failed requests. Each request is classical and atomic with respect
to external oracle calls. The adversary may choose the next statement and
witness using the entire earlier transcript and its retained quantum state.
It retains coherent access before, between, and after requests. All final
measurements and residual registers remain part of the observation.

The ideal coin model samples the entire fresh prover coin vector independently
for each invocation, preserves every public failure, and never discloses unused
secret state. Concrete random-source failures or exposure require the separate
runtime-randomness comparison. Honest typed-valid inputs must also be shown to
produce the canonical packed domain required by the existing algebraic lemmas.

**Leaf transition.** At each leaf, the 140 source rows, five mask evaluations,
salt and index are already fixed. Draw the fresh 64-byte tape, construct its
actual 1,407-byte input, then draw the independent label and program that point.
The source's exact tape projection proves maximum point mass `2^-512` for
every history-selected payload. Read the resulting output and continue the
actual protocol. Programmed entries persist across all later requests.

This fits the input-before-output game in Figure 2 and Theorem 1, Equation (2), of
Grilo, Hoevelmanns, Huelsing and Majenz. If `qhat_r` counts ordinary oracle
queries preceding event `r`, its contribution is
`sqrt(qhat_r*pmax_r) + qhat_r*pmax_r/2`. The theorem allows adaptively selected
sampling distributions and retains subsequent coherent access.
[Primary theorem](https://arxiv.org/pdf/2010.15103).

Within the atomic invocation, the index makes current leaf inputs distinct.
All subsequent honest roles are disjoint from the leaf role, so leaf updates
can be delayed until the request boundary while the selected labels feed the
ordinary Merkle computation. The delayed table must still be applied before
external interaction resumes, including when the request fails.

**Joint mask change.** Retain all previous state, all fresh source coins, all
current leaf inputs and all eventual table updates. With the sampled labels
fixed, the already constructed bijection is

```
D = C(Q,U) + M             Q = T - F(D)
T = F(D) + Q               M = D - C(Q,U).
```

The source-bound `current_forward_source_suffix_matches` recovers the original
leaf payload, including the dependence of the committed heads on `Q`. The
arbitrary-observation transport retains the old masks internally. Thus `(D,T)`
may be sampled uniformly first without assuming that the old leaf inputs
became witness-independent. The full `T` has 3,105 independent field
coordinates: five nonlinear rows of 489 coefficients and five linear rows of
132 nonconstant coefficients.

**Final-input transition.** After the earlier public hash computations and
`D` are fixed, draw the fresh `T`, form the exact framed final PIOP input, then
draw and program its independent digest. Retaining all 3,105 canonical
coefficients gives maximum point mass `p^-3105`. No entropy claim is made
after conditioning on the resulting digest, selected opening points, or
subsequent oracle answers. The next challenge now comes from the independent
digest, so the public-stage interface can select its admissible points before
the remaining algebraic coins are transported.

The new `SmallWoodV8Smz9HonestWholeViewFinalInput.lean` helper constructs those
3,113 words from the actual alternating coefficient equivalence and the raw
eight-word digest prefix. It passes them through the exact source
profile/role/length/u64/counter-zero framing. Word and raw-byte injectivity
follow from the existing exact frame parser, and the finite uniform
pushforward has point mass at most `p^-3105`. This is the honest-side full
coordinate sampler. It does not invoke the compact simulator's 3,045 high-tail
entropy theorem or give the selected digest to the input sampler.

Previously randomized leaf writes can be simulated with the checked retained
override register and two-query compute/select/uncompute construction. A later
collision-exact XOR-mask compiler also handles fixed writes, selected fresh
updates, measurements, and arbitrary repeated-key collisions. It charges each
fixed write's raw lookup and keeps one persistent correction table. The final
program is preserved in both sides of the subsequent comparison. Its input
contains public simulated `D,T`, so keeping it does not require a witness.
The literal final key, its input-first sampler, and the full recursive
fixed-write operational splice are now checked. The composition is supplied
by `SmallWoodV8Smz9FinalLifetimeBounds.lean`, not inferred from the generic
compiler alone.

**Public algebraic view and hidden leaves.** At the independent points, apply
the source witness-opening, corrected PCS, and triangular LVCS bijections in
their established dependency order. The DECS index selector depends on the
earlier LVCS response and is handled by the existing feedback law. All source
proof fields are reconstructed from public output coordinates and the public
statement. Keep the full sampled leaf tree, compute its internal hashes
normally, and retain programs only at the opened leaf inputs. The resulting
eager simulator takes the statement and public context and samples these
public coordinates without consuming a witness.

For one request pivot, the hidden-leaf comparison includes the *entire future
request grammar*. Its baseline oracle, initial quantum state and future gates
may depend on the previous history and the current public output, but have no
current-hidden-tape argument. Every later read consults the same retained
updates. On a late index-sampler failure the existing optional-context law uses
no opened tapes. On an earlier post-leaf public-stage failure the new continued
abort branch supplies the corresponding all-hidden comparison.

This eager simulator does not need the compact simulator's additional internal
Merkle-node programming argument. It requires `N` leaf labels and an ordinary
full tree, which is polynomial in the source prover's work. Identifying the
existing compact Rust simulator with this eager distribution would be an
additional theorem; it is not used in this route.

## Repetition and exact resource meanings

Use a single all-request experiment and replace request pivots in chronological
order. Before a pivot the two adjacent experiments coincide. For each classical
prefix outcome, keep its unnormalized quantum state and the existing oracle;
fresh current coins factor independently of that prefix. The local comparison
is uniform in every baseline table and normalized retained state. Multiply its
bound by the prefix probability and sum. Zero-probability branches contribute
zero. There is no postselection and no multiplication by the number of possible
histories. Coherent measurement dilation or complete instruments must implement
this prefix decomposition in the eventual formal endpoint.

The future retained grammar includes adaptively selected later requests. This
is why a pivot bound already pays for all future queries; resetting the oracle
or proving independently restarted invocations would not establish the same
hybrid. A telescope on these adjacent *whole-experiment* comparisons costs at
most `T` times the uniform hidden-patch suffix bound.

Let `E=Q+H_sha(T)` bound all actual ordinary raw-oracle calls of the source
experiment, including honest leaves, tree nodes, transcript hashes, XOF
counters, rejected samplers, and calls from failed invocations. The first
leaf reduction has at most `E` ordinary calls. The final-input reduction and
the mutable suffix simulation use at most `2E` baseline calls. These costs
give the conservative candidate ideal bound

```
delta_leaf   = N*T*(sqrt(E)/2^256 + E/2^513)
delta_final  = T*(sqrt(2*E*p^-3105) + E*p^-3105)
delta_hidden = 8*T*E/2^256
delta_ideal <= delta_leaf + delta_final + delta_hidden.
```

The point of this expression is to expose every query overhead and both
reprogramming stages. The coordinator's
[source count](honest-sha512-query-budget.md) bounds one canonical
`compile_and_prove` frontend attempt, including its prover and two verifier
calls, by `2^28` raw SHA-512 calls. Take `T` to count every attempted frontend
call and every additional trusted verification invocation. Then the static
source bound is `H_sha(T) <= 2^28*T + H_other`, where wallet KDF, setup,
diagnostic and other separately exposed calls belong to `H_other`. This
static caller analysis is not yet a universal Rust-to-Lean execution
refinement. The source `H_program(T)=2^24*T` is a programming-event envelope
and is not substituted for the actual raw-query count.
No additional collision-free assumption is used: overlays are persistent and
last-write-wins, including repeated inputs across requests.

The bounds `Q<=2^64`, `T<=2^21`, and `H_other<=2^63` imply `E<2^65` under
that static source count. As a numerical screen, `p^-3105 < 2^-512` gives
`delta_leaf < 2^-179 + 2^-404`,
`delta_final <= 2^-202 + 2^-426`, and
`delta_hidden <= 2^-167`. Their sum is below `2^-166`.
This leaves a substantial ideal-game margin, but the `E` premise and concrete
replacement terms have not been proved merely by evaluating this arithmetic.

## What a concrete endpoint must mean

The constructor-free `ConcreteSha512AdaptiveQromInstantiation` and
`AdaptiveRepeatedSmz9WholeViewHybrid` propositions record absent evidence.
Their uninhabitability follows from those declarations and is not a
cryptanalytic impossibility theorem about SMZ9. Replacing them with a true
constant, or inhabiting an endpoint record containing its desired distance,
would not supply the missing reduction.

A literal indistinguishability claim between the public deterministic SHA-512
function and an independently random oracle is false. Choose a fixed public
message and compare one oracle answer with its known SHA-512 value: acceptance
probabilities are one and `2^-512`. Thus the concrete boundary must be an
explicit, reviewed assumption about security of this construction under the
SHA-512 instantiation, or a direct computational construction proof. It cannot
be an information-theoretic random-function replacement justified by digest
width alone. The runtime coin comparison and full source/byte refinement also
remain separate from the finite ideal argument above.

The source-bound post-final byte/error theorem below closes more than the
initial abort branch. Its selected-final fixed-write splice, all-request
composition, public-source erasure and ideal numerical triangle are now
proved. A complete P7 still requires explicit concrete construction assumptions,
full source/runtime refinement and an approved lifetime resource model. None
follows from empty release capability types, and none is replaced here by an
asserted endpoint inequality.

## Current source-bound closure

The following are checked ideal-model statements, not assertions of Rust
compiler refinement or of the security of deterministic SHA-512.

- The actual nonce schedule includes the source's repeated successful XOF,
  all sixteen attempts, pending rejection state, and nonce exhaustion. The
  selected six points carry an admissibility certificate *derived from the
  returned words*. The actual DECS opening hash and fifty-candidate sampler
  compute the twenty indices. No externally supplied selector or successful
  sampler branch substitutes for those reads.
- `SmallWoodV8Smz9DynamicRequest.lean` constructs `D` only after the actual
  DECS gamma read and constructs `T` after the actual PIOP gamma read.
  `SmallWoodV8Smz9DynamicTransport.lean` and
  `SmallWoodV8Smz9DynamicPhysicalTransport.lean` prove the chronological Q/M
  change of coordinates for that interpreter. The observer retains the
  original all-index physical leaf payloads, every tape and label, the full
  future program, and the current oracle. The independent-coordinate law is
  proved; it is not inferred by conditioning the original experiment on its
  output transcript.
- `SmallWoodV8Smz9PostFinalSerializer.lean` constructs all eight matrices in
  source order with **two-byte** row/column headers and canonical eight-byte
  field values, raw 64-byte authentication nodes, the twenty raw leaf tapes,
  salt, nonce, digest, and row-scalar witness mode. It preserves index-error
  precedence over final field-XOF scope failure. Its conservative size bound
  is 128495 bytes, below the actual 131072-byte encoder cap. This is not the
  separate 372-node verifier acceptance claim.
- `SmallWoodV8Smz9SourceTreeGeometry.lean` derives all twenty-four retained
  tree levels and each exact layer width from the actual Merkle interpreter.
  The additional source-path range artifact proves that all twenty-three
  serializer iterations access genuine in-range sibling nodes. Its generic
  loop equality removes the total mathematical lookup's fallback branch;
  no source out-of-bounds behavior is being assumed away.
- `SmallWoodV8Smz9PostFinalProgram.lean` is a program constructed **before**
  choosing the oracle. It charges the actual opening/index reads once and
  returns the literal byte/error constructor. Its proved execution equality
  permits a public-field re-evaluation on the mathematical observer side;
  it does not duplicate those reads in the actual program or supply
  oracle-dependent free advice. Complete future execution and the full
  current leaf overlay survive every error branch.
- `SmallWoodV8Smz9PostFinalPhysical.lean` proves exact full-tape
  disintegration and identifies that literal charged source program with the
  measured same-oracle source endpoint. Its
  `actual_byte_program_to_public_reference_bound` derives
  `hiddenPatchLoss(q) = 4q / 2^256` against an explicit byte/error reference
  with no witness or private-source-coin input. The complete byte/error
  continuation is arbitrary, measured, and bounded by `q`; its initial state
  is normalized and its retained oracle is the same one used by nonce and
  index reads. This theorem is pointwise in the earlier public transcript,
  common oracle and state, with fresh remaining coordinates sampled inside
  the stated post-transport experiment. It does not itself establish a
  repeated-request prefix law.
- `SmallWoodV8Smz9RunHomogeneity.lean`,
  `SmallWoodV8Smz9MeasuredPrefix.lean`, and
  `SmallWoodV8Smz9BytePrefix.lean` now lift that comparison through one actual
  measured prior history. The normalized comparison scales with the exact
  squared norm of each original branch; complete instruments preserve its
  total weight. Initial state and history are fixed before the initial oracle
  draw. The pivot may depend on actual prior outcomes, and the compiler carries
  one initially empty correction log. These results compare two kernels in
  the same history; they do not themselves establish provenance of the pivot's
  fields from the concrete whole source request or match two different
  witness-dependent histories.
- `SmallWoodV8Smz9PublicByteProgram.lean` supplies the reference's actual
  pre-oracle program: source nonce/index reads, public uniform coordinates,
  literal proof/error bytes and only the publicly opened fixed leaf writes.
  It executes the same raw witness-free kernel for every oracle and state.
  `SmallWoodV8Smz9MixedAdapterAccounting.lean` preserves the full future's
  raw query count when fixing its mode. The strictly checked
  `SmallWoodV8Smz9PublicByteAccounting.lean` bounds the current reference by
  `85 + 12 + 20 = 117` raw queries plus that future count and proves that no
  selected fresh-input events remain. Fixed writes are charged, not free.

The recent source and axiom checks used
`-j1 -M3072 -DwarningAsError=true -DautoImplicit=false`. The serializer's
fifteen roots, post-final program's eight roots, and post-final physical
bridge's five roots use only `propext`, `Classical.choice`, and `Quot.sound`.
The tree geometry and path-range roots have the same axiom boundary.
The lane's immutable reviewed source hashes, before central import-path
normalization, are:

| Artifact | SHA-256 |
| --- | --- |
| PostFinalSerializer | `6cbc3f7da03f59609125f862937e6e7b228b0f33a6a6c8f03cabc6ba5167b1ed` |
| PostFinalProgram | `d221776bdea627599076375d99b6cce39006e0d86ebebf43e0a09ae7e24d5a16` |
| PostFinalPhysical | `9a57140c1057fe8ff8bdefea3ff63634747f4fb0e4d009651fc984267ba58f0d` |
| SourceTreeHeight / SourceTreeGeometry | `b334bd6e10f00851ddec6f575160609e6882d4083f07c0e839a39d4d9e958f6b` |
| SourcePathRange | `5d48a872fe9d7b5b8a524bee44a32fa7a4c08c5c33f028f3225e7c2e54ff62fc` |

Central source names and central integration checks are recorded by the
coordinator. These local results do not authorize a release, establish the
universal soundness frontier, or turn the remaining concrete construction
assumption into an unconditional theorem.

## Verification

The second implementation batch adds three source-connected modules:

- `SmallWoodV8Smz9HonestLeafBatch.lean` proves that eager sampling of the
  complete source tape vector equals the sequential input-first leaf game.
  The actual indexed updates are injective and their sequential persistent
  table is exactly `fullSourceOverlay` at all `2^23` leaves. Its query,
  programming and input-mass bounds are derived syntactically, including the
  arbitrary continuation on a failed request.
- `SmallWoodV8Smz9HonestFinalGame.lean` uses an injective finite literal-byte
  raw domain: all 1407-byte inputs form the existing leaf summand, and all
  other byte strings up to an arbitrary bound remain in the complement.
  It proves the actual final input has 25029 bytes and gives its honest and
  input-first randomized execution laws, exact `p^-3105` mass bound, and
  published-GHHM instantiation on computed game probabilities.
- `SmallWoodV8Smz9HonestRequestSchedule.lean` compiles the actual 23-level
  Merkle sequence with all layers retained, the root-binding hash, the
  700-word DECS field-XOF, the repeated source root-binding read, all 1940
  response coefficients in the PIOP input, and the statement-sized PIOP
  coefficient stream. Its field parser stops at the source's first enough
  accepts and preserves rejection-cap failures. The source's unrestricted
  eight `hash_fpp` words are constructed from raw digest bytes and connected
  to the literal final key. The resulting pre-final/final program has a
  derived mass theorem, exact executed-history theorem and conditional GHHM
  bound; it does not take a desired SMZ9 game distance as a premise.

The non-leaf compiler also proves the required local write-deferral rule:
leaf writes can be postponed across an ordinary non-leaf-only phase without
changing its branch, and remain present in the continuation. This is
essential because after the Q/M transport the old leaf addresses depend on
`T`; one cannot call `T` fresh while its dependent physical overlay has
already been installed. The later overlay must instead be retained through
the already derived two-query update compiler.

These three final files passed a combined strict check, including the earlier
game and final-input modules, with `-j1 -M3072 -DwarningAsError=true
-DautoImplicit=false`. All 42 theorem roots in the new three files were
audited; their only axioms are `propext`, `Classical.choice`, and `Quot.sound`
(some use fewer or none). Their SHA-256 values are, respectively:

```
02735586898abc461c360d9e8cb4b5c9d860d29e2ecf2ddb3b06b96b70a52744
4b1b235039ee90d8cbe9f2e0ce40a4a25d434be99bf81c30fbd4baba44b028da
89a6a85c74425737dd65240bf8af32ee6de43151041709ad21d48c0c294fcdc1
```

That earlier batch was not the entire P7 endpoint. Its subsequently completed
post-`h_piop` opening/serialization and continued-error bridges are listed
above. The all-request measured composition and selected-final fixed-write
splice are now integrated into the source-lifetime endpoint. Runtime/byte
refinement and concrete construction-security assumptions are not supplied
by these finite ideal-game proofs.

The first three modules were prepared under a private temporary directory while
the coordinator's source freeze and proving jobs ran. The first two passed
direct strict Lean checking with `-j1 -M3072 -DwarningAsError=true
-DautoImplicit=false`; a combined strict check of all three final sources
then passed.
Twenty-one principal declarations across all three modules were audited with
`#print axioms`; each uses only `propext`, `Classical.choice`, and `Quot.sound`.
There are no custom axiom declarations, admitted proofs, or `native_decide`
calls. Exact rational arithmetic also verified the displayed sum is below
`2^-166`. Source integration is performed centrally by the coordinator. No
release capability, runtime code, proof artifact, or production authorization
has been changed by this lane.
