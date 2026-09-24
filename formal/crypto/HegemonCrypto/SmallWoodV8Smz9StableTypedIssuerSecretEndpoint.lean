import HegemonCrypto.SmallWoodV8Smz9StableHashWiring
import HegemonCrypto.SmallWoodV8Smz9StableCanonicalEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableBurnSourceEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedIssuerSecretEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRequiredNonzeroEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableBurnSourceEndpoint
open HegemonCrypto.SmallWood.V8Smz9StableHashWiring

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

theorem admitted_stable_mint_issuer_nonzero {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mint : statement.stablecoin.direction = .mint) :
    StableNonzeroWords (decodeV8StablecoinIssuerSecret (projectTypedWitness statement packed).stablecoin) := by
  have publicFields := admitted_stable_public_counters domain
  have rawDirection : publicWords.getD 83 0 = 1 := by rw [publicFields.1,mint]; rfl
  obtain ⟨⟨limb,bound,nonzero⟩,_,_⟩ := accepted_stable_mint_required_nonzero domain.2.2 rawDirection
  rw [admitted_issuer_secret_source domain]
  exact List.any_eq_true.mpr ⟨packedWord packed (41491+limb),
    List.mem_map.mpr ⟨limb,List.mem_range.mpr bound,rfl⟩,decide_eq_true nonzero⟩

theorem admitted_stable_burn_issuer_zero {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (burn : statement.stablecoin.direction = .burn) :
    StableZeroWords (decodeV8StablecoinIssuerSecret (projectTypedWitness statement packed).stablecoin) := by
  have publicFields := admitted_stable_public_counters domain
  have rawDirection : publicWords.getD 83 0 = 2 := by rw [publicFields.1,burn]; rfl
  have zero := accepted_stable_burn_issuer_zero domain.2.2 rawDirection
  rw [admitted_issuer_secret_source domain]
  apply List.all_eq_true.mpr
  intro word member
  obtain ⟨limb,limbMember,rfl⟩ := List.mem_map.mp member
  exact decide_eq_true (zero limb (List.mem_range.mp limbMember))


end HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedIssuerSecretEndpoint
