# Decoded polynomials to actual packed source acceptance

The module `SmallWoodV8Smz9CurrentSourceAcceptance.lean` closes the interpreter
step following `SmallWoodV8Smz9DecodedPolynomialSource.lean`. Its input is an
arbitrary decoded source, the actual canonical public words, and satisfaction
of the constructed unbatched PIOP candidate. Its output is the unchanged
`hgv8rp03ProgramComponents.AcceptsPacked` predicate for the explicitly generated
43,904-word witness. It does not take honest lowering, successful evaluation,
decoded semantic validity, or a refinement receipt as a premise.

## Construction and source boundary

`canonical_expression_resolves` treats every actual `FieldExpression`
constructor, including inverse, bit extraction, and equality selection. The
program induction preserves successful `Option` evaluation and the exact
growing list length. The actual 565-node public expression program therefore
succeeds on the admitted public length. The same argument supplies the
nonlinear evaluator on each 686-word lane.

Canonical natural representatives lift field equations back into the source
interpreter. This includes targets and each intermediate CSR sum, not just a
comparison of final mathematical expressions.

Public compilation omits empty zero-target rows and replaces an empty
nonzero-target row with a fallback coordinate. Recovering all raw equations
from the normalized rows needs an additional source fact: actual attempt
19,298, family 39, has coefficient one at packed coordinate 41,528 and target
zero. The normalized system itself therefore forces that coordinate to zero.
An empty nonzero-target normalized row is consequently impossible. This
argument does not assume raw acceptance in order to derive raw acceptance.

The packing bridge reindexes all 686 by 64 field values into the exact
43,904-word array. Every actual nonlinear root is zero at every packing lane;
every retained normalized linear row implies its raw executable equation.
Together with canonical public words and the constructed canonical witness,
these facts give full packed interpreter acceptance.

## Principal declarations

- `canonical_public_expression_program_succeeds`
- `normalized_rows_force_fallback_zero`
- `normalized_rows_supply_all_raw_equations`
- `normalized_rows_supply_csr_source_acceptance`
- `field_roots_zero_supplies_source_acceptance`
- `decoded_source_relation_supplies_packed_acceptance`
- `fully_satisfied_decoded_candidate_supplies_packed_acceptance`

## Validation and remaining obligations

After the successor fallback-attempt refresh, the full module passed strict
direct Lean checking at 21:12 UTC on 2026-09-07. The coordinator then emitted
the refreshed `.olean` under the same strict settings and audited its four
principal declarations. Both the direct check and cache-refresh run exited 0.
The cache-refresh command, run from `formal/crypto`, was:

```sh
lake env lean -j1 -M3072 -DwarningAsError=true -DautoImplicit=false \
  -o .lake/build/lib/lean/HegemonCrypto/SmallWoodV8Smz9CurrentSourceAcceptance.olean \
  HegemonCrypto/SmallWoodV8Smz9CurrentSourceAcceptance.lean
```

The audited source SHA-256 was
`52ff57ed46f3f0abb1f8e9e6e30f54683a88c1ff8be365781e8679c922838f03`.
The refreshed-module axiom audit reported only these standard axioms:

- `canonical_public_expression_program_succeeds`: `propext`, `Quot.sound`.
- `normalized_rows_supply_csr_source_acceptance`: `propext`, `Classical.choice`, `Quot.sound`.
- `decoded_source_relation_supplies_packed_acceptance`: `propext`, `Classical.choice`, `Quot.sound`.
- `fully_satisfied_decoded_candidate_supplies_packed_acceptance`: `propext`, `Classical.choice`, `Quot.sound`.

This is a source-interpreter acceptance result. It is not yet a derivation of
all typed semantics, an actual accepted-proof-to-polynomial extractor, a
Rust implementation refinement, or a complete Fiat--Shamir/QROM theorem.
The pre-batching candidate chronology, actual opening reconstruction, efficient
quantum extraction, concrete universal recovery bound, and full semantic
conjunction remain separate obligations in the complete-security ExecPlan.
