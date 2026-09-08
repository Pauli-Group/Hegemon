import HegemonCrypto.SmallWoodV8Smz9StableTypedPublicEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableTypedPolicyEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableTypedCollateralEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableTypedIssuerSecretEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableCommonEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableIssuerEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableStateRoots

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableEnabledEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCanonicalEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRequiredNonzeroEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedPublicEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedPolicyEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCollateralEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedIssuerSecretEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCommonEndpoint
open HegemonCrypto.SmallWood.V8Smz9StableHashWiring
open HegemonCrypto.SmallWood.V8Smz9StableIssuerEndpoint
open HegemonCrypto.SmallWood.V8Smz9StableStateRoots

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000
set_option Elab.async false
attribute [local irreducible] Hegemon.Transaction.Poseidon2Width16Kernel.permutation

/-- The full unchanged enabled stablecoin semantic predicate follows from actual admission
and arbitrary repaired packed acceptance. No stable-valid or typed-decoder premise is added. -/
theorem admitted_enabled_stable_valid {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (enabled : statement.stablecoin.direction = .mint ∨ statement.stablecoin.direction = .burn) :
    exactV8StablecoinEnabledValid (derivedRelationContext statement) statement.stablecoin
      (projectTypedWitness statement packed).stablecoin := by
  have canonical := admitted_stable_canonical_witness domain enabled
  obtain ⟨height,epochBound,sequenceBound,intentNonzero,magnitudePositive,magnitudeBound,debtBound,mintCap⟩ :=
    admitted_stable_enabled_public_bounds domain enabled
  obtain ⟨asset,policy⟩ := admitted_stable_asset_policy_binding domain
  have common := admitted_stable_common_valid domain enabled
  have active : statement.stablecoin.direction ≠ .disabled := by
    rcases enabled with mint | burn
    · rw [mint]
      decide
    · rw [burn]
      decide
  obtain ⟨beforeRoot,afterRoot⟩ := admitted_stable_state_roots domain active
  have intent : statement.stablecoin.actionIntent = (derivedRelationContext statement).expectedActionIntent := by
    simp only [derivedRelationContext,if_neg active]
  unfold exactV8StablecoinEnabledValid
  rcases enabled with mint | burn
  · have counters := admitted_stable_counter_transition domain true mint
    have mintPolicy := admitted_stable_mint_policy domain mint
    have secret := admitted_stable_mint_issuer_nonzero domain mint
    obtain ⟨commitment,authorization⟩ := admitted_stable_mint_issuer_links domain mint
    have collateral := admitted_stable_mint_collateral domain mint
    refine ⟨canonical,rfl,height,epochBound,sequenceBound,rfl,intentNonzero,intent,
      magnitudePositive,magnitudeBound,asset.symm,policy.symm,common,beforeRoot,counters.1,?_⟩
    rw [mint]
    exact ⟨mintPolicy,secret,commitment,authorization,counters.2.1,counters.2.2.1,mintCap,
      counters.2.2.2.1,debtBound,counters.2.2.2.2,collateral,afterRoot⟩
  · have counters := admitted_stable_counter_transition domain false burn
    have secret := admitted_stable_burn_issuer_zero domain burn
    have authorization := admitted_stable_burn_authorization_zero domain burn
    refine ⟨canonical,rfl,height,epochBound,sequenceBound,rfl,intentNonzero,intent,
      magnitudePositive,magnitudeBound,asset.symm,policy.symm,common,beforeRoot,counters.1,?_⟩
    rw [burn]
    refine ⟨secret,authorization,counters.2.1,?_,counters.2.2.2.1.1,counters.2.2.2.1.2,
      counters.2.2.2.2,afterRoot⟩
    simpa only [Bool.false_eq_true,if_false,Nat.add_zero] using counters.2.2.1

/-- Every direction is discharged from the same actual admitted packed witness. -/
theorem admitted_stable_transition {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    exactV8StableTransition (derivedRelationContext statement) statement.stablecoin
      (projectTypedWitness statement packed).stablecoin := by
  cases direction : statement.stablecoin.direction with
  | disabled => exact admitted_disabled_stable_transition domain direction
  | mint =>
    unfold exactV8StableTransition
    rw [direction]
    exact admitted_enabled_stable_valid domain (Or.inl direction)
  | burn =>
    unfold exactV8StableTransition
    rw [direction]
    exact admitted_enabled_stable_valid domain (Or.inr direction)


end HegemonCrypto.SmallWood.V8Smz9SemanticStableEnabledEndpoint
