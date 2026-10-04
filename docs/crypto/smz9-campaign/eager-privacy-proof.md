# Eager SMZ9 privacy: source-shaped constructive transport

Status: local algebraic module complete and frozen for integration, 2026-09-07.
This document does not authorize production
zero-knowledge claims. Its checked algebraic components are in
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9EagerPrivacy.lean`; the finite quantum
oracle comparisons are separate modules. Runtime behavior, transcript bytes,
admissibility predicates, and release capabilities are unchanged.

## Concrete experiment sequence

Fix the public statement and a valid witness. The intended comparison is between
the entire honest proof/oracle experiment and an eager simulator that builds the
complete tree of `2^23` independently randomized leaf digests. The eager simulator
is not the existing compact simulator with its distribution asserted by fiat.

1. Replace each honest leaf call, chronologically, by sampling its fresh 512-bit
   tape, sampling an independent output, and programming the leaf oracle there.
   `hidden-leaf-qrom-step.md` states the adaptive-reprogramming reduction and query
   accounting. Keep every original input and final overlay as coupling state.
2. Within the atomic honest invocation, defer those leaf-table writes past all
   subsequent nonleaf calls. The full tree uses the sampled leaf outputs and
   ordinary node hashing. The role-domain separation and restricted coherent
   query equalities are in `SmallWoodV8Smz9HonestHybrid.lean`. This step does not
   permit an outside adversary to query a hidden leaf during the deferral.
3. Jointly replace the 3,105 PIOP mask coefficients `Q` and 1,940 DECS mask
   coefficients `M` by the complete DECS response `D` and complete PIOP response
   `T`. The explicit inverse below handles the challenge dependence on `D` and
   the committed-head dependence on `Q`.
4. Apply adaptive reprogramming at the final PIOP-input point, whose `T` contains
   3,105 fresh canonical field coordinates. Sample the resulting opening
   challenge independently. Do not justify this by conditioning on the honest
   challenge or by applying reprogramming to an input that already encodes the
   desired challenge.
5. At these independent admissible opening points, transport the remaining
   witness, PCS and LVCS randomness in that order to their public opening views.
   Later DECS indices are a function of already generated public data and the
   early LVCS response, so use the triangular feedback map, not a fixed-index
   assumption.
6. Recover all serialized algebraic proof fields from those independent public
   coordinates. Keep the complete sampled leaf tree, its authentication paths,
   the opened tapes, and the programs at the opened leaf inputs.
7. Remove only the unopened leaf programs using the hidden-patch quantum
   comparison. Restore the prior table value at a removed current-proof program;
   do not delete an unrelated prior-proof entry. The unopened tapes must remain
   independent of the reference continuation and must not later be disclosed
   through corruption or honest secret-state reuse.

The checked exact equalities in steps 3 and 5 are stronger than a record holding
arbitrary real/simulator probabilities: their input is an explicit finite
uniform coin law and their output law is derived from constructed bijections.
They do not, on their own, establish all seven experiment transitions.

## Joint PIOP/DECS inverse, including feedback

Use the exact source sizes:

```text
Qn: 5 × 489 field coefficients
Ql: 5 × 132 nonconstant field coefficients
M:  5 × 388 field coefficients
U: 140 × 20 LVCS tail coordinates
```

The linear constant coefficient is derived from the zero-sum condition on the
64 packing points. Its polynomial is

```text
Ql(X) = Σ(k=1..132) q[k] (X^k − (1/64) Σ(a=0..63) a^k).
```

The module proves both its point-evaluation formula and zero packing sum. It does
not count 133 independent linear coefficients.

For fixed witness/PCS/LVCS coins, sampled leaf tree `Y`, and all nonleaf oracle
answers, let `C(Q,U)` denote the complete coefficient response of the unmasked
DECS combinations. It uses the actual full 388-node interpolation of the rotated
LVCS rows. Let `F(D)` denote the unmasked PIOP coefficients, with its challenges
computed after seeing the response `D`.

The map and its inverse are:

```text
D = C(Q,U) + M                 Q = T − F(D)
T = F(D) + Q                   M = D − C(Q,U).
```

Both inverse identities are checked. The formal callback arguments `C` and `F`
are deterministic functions, not assumed probability equalities. Their exact
source instantiation remains a refinement obligation. In particular `C` may
depend on `Q`; that dependence cannot invalidate the inverse because `D` is
known before recovering `Q`.

The chronological theorem commutes independent `Y`, applies this bijection at
each fixed retained base state, and places uniform `(D,T)` before that base
state. Its arbitrary observation can retain the old `Q,M` and every old leaf
input. Thus the equality does not silently discard the oracle overlay while
claiming it became witness-independent.

## Correct PCS map: source discrepancy and repair of the proof model

The active source writes randomness at row `64+t` in column `i`, then subtracts
that randomness in the **next** column. For a width-eight nonlinear polynomial,
write `Z_i(X)=Σ(t<6) z[t,i]X^t`. With source coefficient chunks `B_i`, the columns
are

```text
A0 = B0 + X^64 Z0
Ai = Bi + X^64 Zi − Z(i−1)           1 ≤ i ≤ 6
A7 = B7 − X^29 Z6.
```

For a width-two linear polynomial:

```text
A0 = B0 + X^64 Z0
A1 = B1 − X Z0.
```

Only columns after the first are serialized as partial evaluations. Therefore
their actual random shifts at an opening point `r` are

```text
(r^64 Z1−Z0, r^64 Z2−Z1, ..., r^64 Z6−Z5, −r^29 Z6)
−r Z0.
```

The previous “exact PCS blocks” combined the addition and subtraction within
one column. That model is not the runtime randomness map. In particular, for a
linear constant coin, actual output is `−r`, while the legacy block gives
`r^64−r`; these differ at every nonzero `r`. The module proves this statement and
its concrete Goldilocks `r=65` instance. This mismatch is not restricted to a
point rejected by the current admissibility predicate.

The new nonlinear point map is upper-bidiagonal. Its last output recovers
`Z6(r)` by division by `−r^29`; back-substitution recovers every earlier
`Zi(r)`. The six-point Vandermonde then recovers each coefficient vector.
The linear output recovers `Z0(r)` by division by `−r`. Consequently distinct
nonzero opening points suffice. The existing stronger runtime power exclusions
are retained unchanged as a conservative screen; this proof does not change
which challenges the protocol accepts.

The new module proves injectivity, builds the complete 240-coordinate
bijection, and derives its joint uniform law. It also proves the exact
next-column coefficient formulas and matches the source column-polynomial
evaluation to the point map.

Source anchors: `circuits/transaction/src/smallwood_engine.rs` configuration
at 9550–9576; randomness updates at 10206–10223; column stacking at 10228–10242;
public reconstruction at 10454–10504. Existing source comments or old formal
names are not evidence overriding those update statements.

## Public first-column recovery

Source reassembly weights for the nonlinear columns are

```text
1, r^64, r^128, r^192, r^256, r^320, r^384, r^419.
```

The final exponent is `7*64−29=419`. All `Z` terms cancel. For the linear
columns the weights are `1,r^63`. The module proves these telescoping identities
and the resulting public recovery formulas:

```text
NL A0(r) = Qn(r) − Σ(i=1..6) r^(64i) Ai(r) − r^419 A7(r)
L  A0(r) = Ql(r) − r^63 A1(r).
```

Witness width-one columns equal the already emitted witness opening. These
736 recovered column values split into consecutive halves of 368, giving the
12 LVCS public combination heads. The physical coefficient-to-head indexing
is `head[s,c] = coeff(A[368*(s/70)+c],s%70)`.

The module now proves both source chunk identities: `489=7*64+41`, with the
last 41 coefficients shifted by 29; and `133=64+69`, with the last 69 shifted
by one. It also proves the complete 140-row combination-matrix/736-column
reshape identity for every index, and its polynomial form under the natural
source invariant that each unstacked column has degree below 70. This uses
the actual two interleaved Vandermonde row blocks; it does not supply a
head-evaluation equality as an assumption.

The remaining source binding is to compose this calculation with all source
array constructors and the encoder, and to derive the PIOP scalar openings
from the independent public data. The separately authored
`SmallWoodV8Smz9PiopOpeningRecovery.lean` addresses the latter interface; this
module remains independent of that file until coordinator integration.

## Dependent witness/PCS/LVCS law

For fixed independent opening challenge and fixed `(D,T)`:

1. Translate the source witness packing polynomial plus six interpolation-mask
   coordinates to the six witness openings. Its equivalence is proved to equal
   the actual polynomial-evaluation expression.
2. Recover the old witness coins internally. They determine `Q=T−F(D)` and
   hence the base PCS partials. Translate the **correct** PCS map by that base.
3. Recover the old PCS coins internally. They determine the committed heads.
   Apply the existing exact LVCS feedback equivalence, with the later indices
   computed from the already emitted witness/PCS view and early LVCS response.

The constructed dependent product equivalence has output dimensions

```text
witness openings 4116 + PCS partials 240 + LVCS early/later 2800 = 7156.
```

Its joint output is uniform independently of the witness and of both
witness-dependent affine offsets. This is not a claim that those old secret
coins are public: the inverse uses them only within the coupling. The theorem
must still be linked to the complete runtime encoder and public reconstruction.
The total coin count is `7156+3105+1940=12201`.

The equivalence is separately proved to match the explicit chronological
witness, PCS and LVCS outputs. A second law retains an optional failure from
the late DECS-index selector, using a fallback only to establish a bijection
on the discarded failure branch. It never conditions the honest law on a
successful selector result.

The entire 12,201-coordinate accepted sampler allocation is also constructed:
4,116 witness words, five alternating 489/132 mask rows, 240 PCS words,
2,800 LVCS words and 1,940 DECS words. The actual PCS allocation index is
`42*a+7*t+k` for nonlinear coin `(a,k,t)`, and `210+6*a+t` for linear coin
`(a,t)`. This explicit transpose is distinct from the serialized output
ordering. Transporting the previously proved ideal rejection-output law
through this allocation derives the full joint uniform coin law.

## Verification and remaining claims

Direct checks use the package's strict flags:

```text
lake env lean -DwarningAsError=true -DautoImplicit=false \
  HegemonCrypto/SmallWoodV8Smz9EagerPrivacy.lean
```

The final 977-line module passed the strict command above at 15:37 UTC on
2026-09-07. A second strict check of the same source with eleven endpoint
`#print axioms` queries passed at 15:39 UTC. Every queried endpoint depends only
on `propext`, `Classical.choice` and `Quot.sound`. The audit covers the full
allocation, joint-mask chronology, corrected PCS map and counterexample,
source chunks and polynomial evaluations, chronological/abort-preserving
joint law, and the source-polynomial/public-head bridge. Source scanning found
no `sorry`, `axiom`, `admit` or `native_decide` token. Diff whitespace checking
also passed.

No assumed whole-view probability equalities, runtime changes, production
flag changes, shared build-output writes, or release authorization are part
of this work. The source and document together occupy about 62 KB; disk
availability remained above the task's 40 GiB floor.

Outstanding integration gates include full source-array and public-field
encoder reconstruction; all sampler failure
branches; chronological classical-quantum experiment composition and its
numeric bound; repeated-proof state/overlay accounting; runtime refinement and
independent security authorization. A mathematically valid eager construction
must not be reported as the current compact simulator's proved distribution.
