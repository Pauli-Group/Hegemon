# SmallWood strict-view simulator construction boundary

Status: retained negative evidence plus one executable algebraic component;
**not** a complete-ZK theorem, compiled refinement, or production
authorization.  The architecture tournament has source-disqualified the
current SmallWood Boolean adapter: at least 1,258,569 hash-only rows imply an
inner-proof lower bound of 75,589,554 bytes, and the resulting column shape
exceeds the `SMZ2` wire's `u16` limit before non-hash logic or ZK repair.

## Exact view to simulate

The simulator target is the canonical accepted inner proof view, not a list of
individual masking claims.  For a fixed valid public statement it must jointly
produce the salt, canonical PIOP nonce, `h_piop`, PIOP quotient high
coefficients, PCS combination tails, LVCS subset evaluations, partial witness
evaluations, 23 compact Merkle authentication paths, 23 opened 64-byte leaf
tapes, DECS masking evaluations, DECS high coefficients, opened witness row
scalars, and auxiliary words.  A revived fresh-V6 construction would have to
produce exactly the same length grammar as `SMZ2`, reject trailing bytes, and
account for every abort or retry used by the compiled prover.

`SMZ1` is only inactive historical-`Sha512Level5` strict-tape evidence and can
never be reinterpreted as V6.  The reserved fresh identity is `SMZ2` paired
only with `Sha512V6` and the disjoint-coset domain; every cross-wire/backend
pair is rejected.  The concrete V6 adapter still fails closed rather than
routing either identity through the historical backend.  Neither wire has
complete-ZK or production authority.

## Exact algebraic simulator seams

### Witness-polynomial openings

Each packed witness row fixes values at the 64 packing points and samples five
independent Goldilocks values through `poly_interpolate_random`.  Equivalently,
the resulting degree-68 polynomial is a fixed interpolant plus the packing
vanishing polynomial times an arbitrary degree-four polynomial.  Evaluation at
five distinct non-packing PIOP points is a bijective linear image of those five
random values.  Thus the five opened row scalars can be sampled uniformly
without the witness.  This local fact is not yet enough: the simulator must
also match their correlations with the PIOP quotient messages and partial
evaluations.

### Local PIOP quotient and partial-opening view

`circuits/transaction/examples/smallwood_piop_zk_audit.rs` is a
dependency-free executable counterpart of the engine's exact Goldilocks
`poly_restore` equations.  It constructs the triangular local simulator using
only sampled witness-opening values, constraint evaluations at those openings,
public linear targets, and independent view coordinates:

- for a nonlinear mask of degree `D`, five mask evaluations plus the
  `D + 1 - 5` combined-message high coefficients form a rank-`D + 1` affine
  view;
- for the degree-131 zero-sum linear mask, five mask evaluations plus 126
  combined-message high coefficients form a rank-131 affine view, provided the
  verifier's packing-sum correction factor is nonzero; and
- for every width-`w` PCS split, the serialized `w - 1` tail values are free
  and the first value is uniquely recovered from the opened row scalar.

For the representative five valid opening points the executable reports
nonlinear ranks `73/73`, `141/141`, `277/277`, and `481/481` for constraint
degrees 2, 3, 5, and 8, linear rank `131/131`, and correction factor
`4091547049468779063`.  The degree-5 case covers the current V6 SHAKE
lowering's maximum constraint degree; degree 8 checks the engine ceiling.  The
generic rank argument is interpolation at five distinct non-packing points;
the linear case additionally requires the correction factor to be nonzero.
The executable also gives an exact counterexample to the historical nonce
predicate: the distinct non-packing points
`[1000, 1001, 1002, 1003, 9145141821497892284]` have correction factor zero.
The current collision-only prover predicate accepts this set while the
verifier rejects it, so an honest prover can emit a verifier-rejected view.
This is a concrete completeness/distribution-refinement defect, not a
statistical or QROM proof.

Run the executable certificate with:

```sh
rustc --edition=2021 --test \
  circuits/transaction/examples/smallwood_piop_zk_audit.rs \
  -o /tmp/smallwood_piop_zk_audit_tests
/tmp/smallwood_piop_zk_audit_tests
```

This establishes a local affine-rank/refinement component, not equality of the
compiled prover distribution.  It does not simulate the commitment to those
same mask polynomials, Merkle/DECS correlations, Fiat--Shamir challenges,
conditioned aborts, repeated/adaptive proofs, or the QROM.

### LVCS/DECS opened rows

Every 375-value LVCS row receives 23 independent random tail values, is rotated
to `[23 random | 375 data]`, and is viewed as evaluations at interpolation
nodes `0..397`.  For 23 distinct query points outside that interpolation
domain, the linear action of the random tail on the queried evaluations is,
up to invertible row and column scalings, the Cauchy matrix

```
C[i,j] = 1 / (query[i] - (375 + j)).
```

Its determinant is nonzero because all query points and random-tail nodes are
distinct.  The 23 opened values of every LVCS row are therefore uniform and
can be simulated exactly, independently of the 375 data values.  The
dependency-free audit in
`circuits/transaction/examples/smallwood_zk_domain_audit.rs` checks rank
`23/23` for representative strict query sets over the exact Goldilocks field;
the Cauchy determinant argument covers every valid distinct query set.

The retained radix-2 subgroup violates the required premise: leaf 163840 is
field point 64, an interpolation node, and yields the independently reproduced
rank-69 witness recovery.  Only the profile-distinct disjoint coset can use the
tail-bijection argument.

### DECS combined and masking polynomials

For each of the five DECS combinations, the prover samples one uniform
degree-397 masking polynomial and adds it to the challenge-weighted LVCS rows.
Conditioned on the rows and challenge, the combined polynomial is uniform.
The serialized 23 masking evaluations plus the 375 high coefficients are a
bijective representation of that mask/combined-polynomial relation.  A joint
interactive simulator can therefore:

1. sample the 23 opened LVCS row values using the tail bijection;
2. sample each complete combined polynomial uniformly;
3. set each opened masking value to `combined(q) - gamma * rows(q)`; and
4. serialize the combined polynomial's coefficients 23 through 397.

This preserves the verifier's exact polynomial restoration equation.  It does
not by itself simulate the Merkle root or PIOP messages.

### Merkle leaves

For the inactive strict inner mode, the prover samples an independent 64-byte
tape for every one of the `N = 2^20` leaves.  Each strict leaf hash binds the
global salt, exact leaf index, 64-byte tape, committed-row evaluations, masking
evaluations, their two counts, and the transcript counter.  The proof opens
exactly 23 derived, distinct, sorted indexes and exactly 1,472 tape bytes.
Merkle authentication consumes the `u32` table indexes; the corresponding
coset field points are used only by LVCS and polynomial reconstruction.

In a classical ROM simulator, unopened leaves may be lazily programmed and
opened leaves are programmed from the simulated algebraic values and fresh
tapes.  That sentence is not a QROM proof.  The strict reduction must account
for measure-and-reprogram loss and the global leaf-oracle query budget.  The
512-bit tape term has generic scale `Q_H^2 / 2^512`; 256-bit tapes are rejected
because the analogous term reaches one at `Q_H = 2^128` before constants and
union terms.

## Fiat--Shamir, abort, and retry behavior

The simulator must preserve the compiled causal order and condition on the
same events as the prover:

1. the Merkle root and exact statement binding determine the DECS coefficient
   challenge;
2. the PCS commitment transcript and public binding determine PIOP challenges;
3. `h_piop` determines the canonical first collision-free PIOP nonce and five
   opening points, with the exact 16-trial failure event; and
4. the DECS opening hash feeds the fixed 50-candidate sampler, which takes the
   first 23 distinct accepted indexes and has no prover-selected nonce.

The current code returns an error if either bounded sampler fails.  A theorem
must pin whether the production caller retries the whole proof with fresh
randomness or exposes that failure; the simulator must do the same.  It may not
silently resample only a challenge or condition away an event without adding
its exact probability to the distinguishing bound.

## Retained blockers

The local PIOP affine view has an executable rank/simulator certificate.  The
whole-proof simulator was deliberately not built after the Boolean adapter
failed the architecture size and wire gates.  If SmallWood is ever revived
with a fundamentally different Boolean-native arithmetization and wire, its
required closure remains:

- compiled engine integration/refinement of the isolated `Sha512V6` backend,
  consuming only the canonical V6 domains and exact `HGV6PB02` preamble;
- an executable whole-view simulator with deterministic abort injection;
- small-field exhaustive distribution/refinement tests and exact Goldilocks
  rank certificates;
- Lean statements for the witness-opening, LVCS-tail, DECS-mask, Merkle-ROM,
  PIOP, and composed Fiat--Shamir simulator steps;
- a QROM composition bound at both global `2^64` and `2^128` query budgets;
- Rust prover/RNG/parser/verifier refinement to those statements; and
- independent receipts trusted by the fail-closed checker.

The current source-disqualified adapter has none of that authority:
`complete_zk`, `pq128`, and `production_authorized` remain false.
