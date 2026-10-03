# Daybreak stable balance-asset membership fix

## Outcome

The typed Rust public-statement boundary now rejects an enabled stablecoin mint or burn unless its stable asset occurs exactly once in the canonical four-slot balance-asset list. Disabled stablecoin statements retain the native-only default layout and require no stable-asset membership.

This closes the concrete semantic-completeness disagreement recorded in `semantic-completeness-counterexample.md`: an enabled burn of asset 1001 with balance assets `[0, padding, padding, padding]` was admitted by the typed semantics even though generated HGV8RP03 root 1042 rejects every packed witness.

## Rust boundary

`SmallwoodPoseidon2V8PublicStatement::validate_public_structure` already validates the canonical balance layout and then calls `validate_compatibility_stablecoin`. The compatibility validator now counts balance slots equal to the enabled compatibility asset and requires the count to be one. The existing canonical layout independently requires native asset 0 first, strictly increasing non-padding assets, and trailing padding, so duplicate assets are also structurally invalid. The explicit count keeps the frontend contract aligned with the packed membership constraint.

Focused regressions cover:

- the existing enabled mint fixture with asset 1001 in one balance slot;
- the prior enabled burn public shape with asset 1001 absent from the balance list, through both direct validation and public-word decoding;
- an enabled statement with missing membership; and
- the disabled native-only statement, whose behavior is unchanged.

No generated relation source, relation digest, proof bytes, manifest, route, or production authorization changed.

## Required Lean mirror

In `formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean`, strengthen the typed public semantics at `CanonicalCompatibility`, where both `.mint` and `.burn` already require `compatibility.enabled = 1` and bind `compatibility.assetId = stable.assetId`.

Add the balance-assets list to the predicate boundary, then require exactly one occurrence for each enabled direction. A precise shape is:

```lean
def CanonicalCompatibility
    (balanceAssets : List Nat)
    (compatibility : V8StablecoinCompatibility)
    (stable : V8StablecoinPublic) : Prop :=
  -- existing common conditions
  match stable.direction with
  | .disabled =>
      -- existing disabled conditions; no membership requirement
  | .mint =>
      -- existing mint conditions
      balanceAssets.count compatibility.assetId = 1
  | .burn =>
      -- existing burn conditions
      balanceAssets.count compatibility.assetId = 1
```

Update the `CanonicalPublicStatement` call site from `CanonicalCompatibility statement.compatibility statement.stablecoin` to `CanonicalCompatibility statement.balanceAssets statement.compatibility statement.stablecoin`, and update direct theorem/test invocations accordingly. Using `List.count` states the exact-one invariant directly; `CanonicalBalanceAssets` should remain the independent ordering/padding predicate. This change intentionally strengthens the typed target to match the unchanged packed relation rather than weakening or regenerating HGV8RP03.

## Claim boundary

The focused frontend repair removes the known root-1042 counterexample once the Lean mirror is applied. It does not prove the full semantic-to-packed completeness theorem, compiler/refinement equivalence, proof-system soundness, zero knowledge, PQ128 security, or production eligibility. The separate absent-retirement carry/materializer issue remains unresolved and outside this fix.
