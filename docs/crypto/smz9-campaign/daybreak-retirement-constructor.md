# Daybreak no-retirement constructor validation

## Verdict

The reported edge was real in the honest auxiliary constructor and is fixed in
source. It was not a defect in the HGV8RP03 relation and did not show that the
typed transition was intrinsically unencodable.

For a mint with `retired_at = None` and
`enabled_at = parent_height = 4294967295`, the old `build_aux` assignment set
both retirement gaps to zero but computed both retirement low-limb carries as
one. The executable packed relation gates the retirement addition residuals by
`mint * retired_present` and separately requires the two gaps and carries to be
zero when that gate is inactive. The honest lowering therefore rejected its own
otherwise valid typed input.

An alternative packed witness does exist: keep the two inactive retirement gaps
and the two retirement carries at zero. With `retired_present = 0`, multiplication
lanes 25 through 28 have left input zero, so their residual right inputs do not
affect their required zero products. Canonical-helper lanes 29 through 32 then
have left input one, helper input zero and output zero. No unchanged constraint
requires the absent-retirement additions themselves to hold.

The repair only changes honest auxiliary materialization: retirement carries are
now derived when `retired_at.is_some()` and are canonical zero otherwise. It does
not change a constraint, public word, relation identity, generated artifact,
digest, typed semantic rule, wire format or production-authority decision.

## Validation rubric

- [x] The claimed typed input reaches normal mint validation.
- [x] The old honest helper values conflict with the inactive canonical-helper constraints.
- [x] The unchanged relation has a concrete alternative helper assignment.
- [x] The patch changes only honest helper construction and preserves active-retirement behavior.
- [x] A focused exact library regression passes.

## Source trace

`validate_mint_policy` accepts `retired_at = None`; retirement ordering and
height checks occur only inside its `Some(retired_at)` branch. The ordinary
typed transition then performs the same public/config/root/counter checks as any
other mint. The regression constructs valid roots and counters at the boundary
height and reaches `build_smallwood_poseidon2_v8_relation_material` successfully.

In `smallwood_poseidon2_v8_relation.rs`, absent retirement already selects zero
for `retirement_order_gap` and `retirement_height_gap`. Before this patch, the
next helper block nevertheless evaluated the low 32-bit sums with the literal
`+ 1`; at `u32::MAX`, both sums carry. The patched block makes just those two
carries conditional on retirement presence.

In `smallwood_poseidon2_v8_semantics.rs`, `stable.retirement_gate_bindings` and
`stable.retirement_residual_bindings` gate the four addition checks through
`mint * retired_present`. `stable.retirement_canonical_helpers` independently
multiplies `1 - retirement_gate` by both gaps and both carries and requires zero.
The lowering copies the materializer's booleans and gaps into those lanes, which
is why the old one-valued carries failed and why zero carries are an accepting
alternative.

## Focused verification

The added regression first proves that the triggering low-limb arithmetic wraps,
then constructs the normal typed mint and asserts canonical zero retirement gaps
and carries in the generated relation material.

Command:

```text
cargo test -p transaction-circuit --lib smallwood_poseidon2_v8_relation::tests::absent_retirement_uses_canonical_zero_helpers_at_low_limb_wrap -- --exact
```

Result: one test passed, zero failed. The package emitted pre-existing unused-code
warnings outside the changed file. No broad build, node, network, proof generation,
generated-source refresh or production gate was run.

## Boundary

This closes the honest-constructor completeness edge only. It does not alter or
resolve the separate root-1042 semantic-to-packed completeness counterexample,
prove full packed-to-typed adequacy, refresh retained proof provenance, or grant
SMZ9 production authority.
