# Actual HGV8RP03 program polynomials

`formal/crypto/HegemonCrypto/SmallWoodV8Smz9ProgramPolynomials.lean` interprets the
actual `Poseidon2V8RelationProgram.FieldExpression` constructors. It does not
identify them with the older `ProductionConstraintExpression` program.

The exact 8,271-node graph and 830 ordered roots come from
`SmallWoodV8Smz9RelationProgramComponentsGenerated`. A 128-entry-block degree
certificate is checked against every actual instruction with ordinary `decide`.
The certificate requires each inverse/bit input and both inputs to each equality
comparison to have formal degree zero. A witness input has degree one; addition,
subtraction, multiplication, negation, and selected branches propagate their
actual degree bounds. The concrete graph has twelve inverse nodes and fifty-one
equality selections, with no bit or negation instructions. Every root has formal
degree at most eight.

## Proof endpoints

- `constraint_polynomials_degree_le`: arbitrary row polynomials of degree at most
  69 yield each of the actual 830 constraint polynomials with degree at most 552.
- `constraint_polynomials_commute`: evaluating those polynomials at any Goldilocks
  point equals executing the actual expression constructors on the row openings.
- `fieldAt_refines_source`: a successful canonical source `evalExpressionNodes`
  execution supplies that field execution exactly. Canonical residues are proved
  from the source computation; subtraction, inverse, bit, and equality selection
  are explicitly covered. Evaluator equality is the conclusion, not a premise.
- `constraint_polynomial_refines_source`: composes polynomial commutation with the
  actual natural-representative interpreter trace.
- `accepted_source_constraints_vanish`: source nonlinear acceptance at a packing
  assignment makes all 830 polynomial constraints zero at that point, whenever
  the supplied row polynomials open to that assignment.

The total node interpreters use earlier-node recursion. Their fallback values
are irrelevant to the source bridge because the already-proved exact program
canonicality establishes every operand and root bound. Inverse and bit are
constant-specialized only after the checked degree-zero condition; there is no
witness-dependent inverse represented as an ordinary polynomial.

The public-input and row interfaces use `Nat` indices with zero-default source
lists. A finite 686-row family can be extended by zero outside its valid indices
when applying the opening theorems. Source-evaluation premises are successful
execution facts, not certificates asserting the desired algebraic equality.

## Verification and authority

Direct check from `formal/crypto`:

```sh
lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9ProgramPolynomials.lean
```

This module does not prove Rust verifier refinement, Fiat–Shamir/QROM security,
PCS extraction, complete semantic adequacy, or production authorization. Those
remain independent obligations. The coordinator owns integration into the full
formal gate and the final source-consumer soundness theorem.
