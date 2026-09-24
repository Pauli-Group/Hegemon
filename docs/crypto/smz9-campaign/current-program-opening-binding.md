# Current-program opened-leaf binding

The companion module is
`formal/crypto/HegemonCrypto/SmallWoodV8Smz9CurrentProgramOpeningBinding.lean`.
Strict direct Lean checking passed with `warningAsError=true` and
`autoImplicit=false`. Nine endpoint axiom audits passed with only `propext`,
`Classical.choice`, and `Quot.sound`. Shared campaign-gate integration is owned
by the coordinator and remains distinct from these local checks.

## Concrete source-to-public chain

The module constructs the exact 736 source PCS column polynomials: 686 witness
columns, five groups of eight nonlinear-mask columns, and five groups of two
linear-mask columns. Its source-column definition equals the current-program
constructor after the recovered Q coins are inserted. The nonlinear source uses
the corrected next-column subtraction, including the final degree-29 shift;
the linear source uses its degree-1 next-column subtraction.

It derives the following reconstruction chain without assuming an output-law,
distance, raw-suffix equality, or abstract adapter:

1. The published column openings are the actual cross-column PCS map; weighted
   column reassembly cancels the PCS randomization and restores Q(r).
2. All physical column degrees are below 70, derived from witness degree at
   most 69 and the concrete mask chunks and six-coefficient PCS randomizers.
3. The 70-by-736 coefficient reshape therefore makes the public combination
   heads exactly the appropriate two halves of those 736 polynomial openings.
4. The selected 12-row matrix inverse and the other 128 row openings recover
   the actual 140 LVCS row evaluations at every selected point.
5. Subtracting the gamma-weighted rows from the same full DECS response recovers
   the actual five DECS-mask openings.
6. Consequently the canonical 1,184-byte opened leaf suffix agrees exactly:
   both count words, all 145 canonical field words, and the zero counter.
   Adding the same public header, index and fresh tape preserves the complete
   1,407-byte leaf input equality.

The actual current-program public Q-opening computation is supplied by the
checked `CurrentProgramPiop` module. High coefficient projections remain those
of the same full D,T responses; the inverse-response lemma preserves both
complete response objects.

## Source witness and accepted program

The source witness interpolation has degree at most 69 and evaluates to the
original values at all 64 packing nodes: Lagrange interpolation supplies the
base evaluations and each randomized basis polynomial vanishes there. The
zero-extended 686-row polynomial vector therefore matches the exact list of
canonical source packing values.

Actual successful evaluation of the fixed 8,271-node/830-root interpreter at
each packing assignment then discharges nonlinear vanishing. The final
source-witness suffix theorem retains public linear weighted-value validity,
admissible PIOP points, the selected LVCS matrix rank, and the elementary
packing/interpolation field nondegeneracy premises. No nonlinear vanishing or
physical column-degree premise remains in that source-witness specialization.

## Boundary

This is deterministic source-model/serializer binding, not the full quantum
privacy theorem. Integration must still instantiate the indexed target context
and the current-program oracle-game constructor, carry aborts and independent
unopened tapes through the complete chronological game, and apply the checked
hidden-table comparison and the external reprogramming theorem with valid
query accounting. Exact Rust execution, public CSR generation and acceptance
refinement are not implied by this algebraic binding alone. No production
authority or verifier/profile change follows.

The coordinator owns shared cache, inventory and campaign-gate integration.
The passed verification command, from `formal/crypto`, is:

```sh
lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9CurrentProgramOpeningBinding.lean
```

The audited endpoints are source-column equality, physical column degree,
public combination-head reconstruction, source rows/masks reconstruction,
complete opened suffix reconstruction, exact packing-row evaluation, accepted
source constraint vanishing, original-response preservation, and the accepted
source-witness suffix specialization. No custom cryptographic axiom, supplied
probability equality or assumed raw-suffix equality appears in those proofs.
