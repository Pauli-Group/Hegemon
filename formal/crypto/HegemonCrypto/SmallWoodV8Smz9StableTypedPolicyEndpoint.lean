import HegemonCrypto.SmallWoodV8Smz9StableCanonicalEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableRequiredNonzeroEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableRetirementEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedPolicyEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCanonicalEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRequiredNonzeroEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

theorem admitted_stable_mint_policy {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (direction : statement.stablecoin.direction = .mint) :
    exactV8StablecoinMintPolicyValid
      (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin)
      statement.stablecoin.parentHeight := by
  have source (word : Nat) (bound : word < 55) := admitted_stable_config_word_source domain bound
  have publicFields := admitted_stable_public_counters domain
  have rawDirection : publicWords.getD 83 0 = 1 := by rw [publicFields.1,direction]; rfl
  have height := publicFields.2.2.1
  obtain ⟨active,disputed,present,ratio⟩ := accepted_stable_mint_basic_policy domain.2.2 rawDirection
  obtain ⟨enabled,oracleDate,oracleAge,attestationDate,attestationAge⟩ :=
    accepted_stable_mint_freshness domain.2.2 rawDirection
  have retirement := accepted_stable_mint_retirement domain.2.2 rawDirection
  obtain ⟨_,numerator,denominator⟩ := accepted_stable_mint_required_nonzero domain.2.2 rawDirection
  unfold exactV8StablecoinMintPolicyValid decodeV8StablecoinConfig
  simp only [source 2 (by decide),source 3 (by decide),source 4 (by decide),source 5 (by decide),
    source 13 (by decide),source 17 (by decide),source 18 (by decide),source 15 (by decide),
    source 16 (by decide),source 20 (by decide),source 22 (by decide),source 23 (by decide),
    source 21 (by decide),Nat.reduceAdd]
  rw [height] at enabled oracleDate oracleAge attestationDate attestationAge
  refine ⟨active,enabled,?_,ratio,numerator,denominator,oracleDate,oracleAge,attestationDate,
    present,attestationAge,disputed⟩
  intro retired
  have result := retirement retired
  rw [height] at result
  exact result


end HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedPolicyEndpoint
