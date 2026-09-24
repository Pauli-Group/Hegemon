import HegemonCrypto.SmallWoodV8Smz9StableCanonicalEndpoint
import HegemonCrypto.SmallWoodV8Smz9StablePublicNonzeroEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedPublicEndpoint

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
open HegemonCrypto.SmallWood.V8Smz9SemanticStablePublicNonzeroEndpoint

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

theorem admitted_stable_intent_word {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (limb : Nat) (bound : limb < 7) :
    publicWords.getD (87+limb) 0 = statement.stablecoin.actionIntent.getD limb 0 := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,intent,_⟩ := domain.2.1
  have encoded : publicWords.getD (83+(4+limb)) 0 =
      (encodeStablecoinPublic statement.stablecoin).getD (4+limb) 0 := by
    rw [←domain.1]
    exact encoded_stable_public_word statement domain.2.1 (4+limb)
  have inIntent : limb < statement.stablecoin.actionIntent.length := by
    rw [intent.1]
    exact bound
  have atIntent : (encodeStablecoinPublic statement.stablecoin).getD (4+limb) 0 =
      statement.stablecoin.actionIntent.getD limb 0 := by
    simp only [encodeStablecoinPublic,List.append_assoc,List.getD_eq_getElem?_getD]
    rw [List.getElem?_append_right (by simp)]
    simp only [List.length_cons,List.length_nil,Nat.reduceAdd,Nat.add_sub_cancel_left]
    rw [List.getElem?_append_left inIntent]
  rw [atIntent] at encoded
  simpa only [show 83+(4+limb)=87+limb by omega] using encoded

theorem stable_nonzero_words_of_getD (words : List Nat) (limb : Nat)
    (bound : limb < words.length) (nonzero : words.getD limb 0 ≠ 0) : StableNonzeroWords words := by
  have member : words.getD limb 0 ∈ words := by
    simp only [List.getD_eq_getElem?_getD,List.getElem?_eq_getElem bound,Option.getD_some]
    exact List.getElem_mem bound
  exact List.any_eq_true.mpr ⟨words.getD limb 0,member,decide_eq_true nonzero⟩

theorem admitted_stable_enabled_public_bounds {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (enabled : statement.stablecoin.direction = .mint ∨ statement.stablecoin.direction = .burn) :
    statement.stablecoin.parentHeight < stablecoinScalarBound ∧
      statement.stablecoin.after.epochId < stablecoinScalarBound ∧
      statement.stablecoin.after.sequence < stablecoinScalarBound ∧
      StableNonzeroWords statement.stablecoin.actionIntent ∧
      0 < statement.stablecoin.magnitude ∧ statement.stablecoin.magnitude < stablecoinValueBound ∧
      statement.stablecoin.after.totalDebt < stablecoinValueBound ∧
      statement.stablecoin.after.mintedInEpoch ≤
        (decodeV8StablecoinConfig (projectTypedWitness statement packed).stablecoin).maxMintPerEpoch := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,height,intent,_⟩ := domain.2.1
  obtain ⟨_,magnitude,_,epoch,minted,debt,sequence⟩ := admitted_stable_public_counters domain
  have rawDirection := admitted_stable_enabled_direction domain enabled
  obtain ⟨magnitudeNonzero,limb,limbBound,intentNonzero⟩ :=
    accepted_stable_public_required_nonzero domain.2.2 rawDirection
  have sequenceBounds := accepted_stable_sequence_epoch_bounds domain.2.2
  have valueBounds := accepted_stable_nine_value_bounds domain.2.2
  have cap := (accepted_stable_epoch_and_cap_inequalities domain.2.2).2.2
  have capSource := admitted_stable_config_word_source domain (word := 14) (by decide)
  rw [admitted_stable_intent_word domain limb limbBound] at intentNonzero
  refine ⟨height,?_,?_,?_,?_,?_,?_,?_⟩
  · have bound := sequenceBounds.2.2.2.1
    rw [epoch] at bound
    unfold stablecoinScalarBound
    norm_num only [Nat.reducePow] at bound ⊢
    omega
  · simpa only [sequence,stablecoinScalarBound] using sequenceBounds.2.1
  · exact stable_nonzero_words_of_getD _ limb (by rw [intent.1]; exact limbBound) intentNonzero
  · rw [magnitude] at magnitudeNonzero
    omega
  · simpa only [magnitude,stablecoinValueBound] using valueBounds.2.2.1
  · simpa only [debt,stablecoinValueBound] using valueBounds.2.2.2.2.2.2.1
  · simpa only [decodeV8StablecoinConfig,capSource,Nat.reduceAdd,minted] using cap

theorem admitted_stable_burn_authorization_zero {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (direction : statement.stablecoin.direction = .burn) :
    StableZeroWords statement.stablecoin.issuerAuthorization := by
  obtain ⟨_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,compatibility,_⟩ := domain.2.1
  have fields := compatibility.2.2.2.2.2
  simp only [direction] at fields
  obtain ⟨_,_,_,_,_,_,_,_,_,issuer,_⟩ := fields
  exact List.all_eq_true.mpr (by intro word member; exact decide_eq_true (issuer word member))


end HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedPublicEndpoint
