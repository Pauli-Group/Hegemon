import HegemonCrypto.SmallWoodV8Smz9StableDecimalEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableTypedCounterEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableCanonicalEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticStableDecimalEndpoint

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

theorem admitted_stable_enabled_direction {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (enabled : statement.stablecoin.direction = .mint ∨ statement.stablecoin.direction = .burn) :
    publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2 := by
  have direction := (admitted_stable_public_counters domain).1
  rcases enabled with mint | burn
  · exact Or.inl (by rw [direction,mint]; rfl)
  · exact Or.inr (by rw [direction,burn]; rfl)

theorem accepted_stable_small_config_bounds {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedWord packed 41408 < 2^32 ∧ packedWord packed 41409 < 2^32 ∧
      packedWord packed 41421 < 2^32 ∧ packedWord packed 41425 < 2^32 ∧
      packedWord packed 41426 < 2^32 ∧ packedWord packed 41453 < 2^32 := by
  refine ⟨?_,?_,?_,?_,?_,?_⟩
  · exact (accepted_stable_even_range accepted (spec := ⟨0,false,41408,0,0,16⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted (spec := ⟨1,false,41409,0,16,16⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted (spec := ⟨2,false,41421,0,32,16⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted (spec := ⟨3,false,41425,0,48,16⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted (spec := ⟨4,false,41426,0,64,16⟩) (by decide)).2
  · exact (accepted_stable_even_range accepted (spec := ⟨5,false,41453,0,80,16⟩) (by decide)).2

theorem admitted_stable_canonical_witness {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (enabled : statement.stablecoin.direction = .mint ∨ statement.stablecoin.direction = .burn) :
    CanonicalV8StablecoinWitnessEncoding (projectTypedWitness statement packed).stablecoin := by
  have source (word : Nat) (bound : word < 55) := admitted_stable_config_word_source domain bound
  have small := accepted_stable_small_config_bounds domain.2.2
  have active := accepted_stable_config_flag_boolean domain.2.2 (slot := 0) (by decide)
  have retired := accepted_stable_config_flag_boolean domain.2.2 (slot := 1) (by decide)
  have disputed := accepted_stable_config_flag_boolean domain.2.2 (slot := 2) (by decide)
  have present := accepted_stable_config_flag_boolean domain.2.2 (slot := 3) (by decide)
  change packedWord packed 41410 = 0 ∨ packedWord packed 41410 = 1 at active
  change packedWord packed 41412 = 0 ∨ packedWord packed 41412 = 1 at retired
  change packedWord packed 41429 = 0 ∨ packedWord packed 41429 = 1 at disputed
  change packedWord packed 41430 = 0 ∨ packedWord packed 41430 = 1 at present
  have decimals := (accepted_stable_decimal_scale domain.2.2 (admitted_stable_enabled_direction domain enabled)).1
  have noRetirement := accepted_stable_no_retirement domain.2.2
  have shape := project_stable_words_shape domain.2.2.2.1 statement
  refine ⟨?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_,?_⟩
  · exact ⟨shape.1,List.all_eq_true.mpr (by intro word member; exact decide_eq_true (shape.2 word member))⟩
  · simpa only [source 0 (by decide),Nat.reduceAdd] using small.1
  · simpa only [source 1 (by decide),Nat.reduceAdd] using small.2.1
  · simpa only [BooleanWord,source 2 (by decide),Nat.reduceAdd] using active
  · simpa only [BooleanWord,source 4 (by decide),Nat.reduceAdd] using retired
  · simpa only [source 13 (by decide),Nat.reduceAdd] using small.2.2.1
  · simpa only [source 17 (by decide),Nat.reduceAdd] using small.2.2.2.1
  · simpa only [source 18 (by decide),Nat.reduceAdd] using small.2.2.2.2.1
  · simpa only [BooleanWord,source 21 (by decide),Nat.reduceAdd] using disputed
  · simpa only [BooleanWord,source 22 (by decide),Nat.reduceAdd] using present
  · simpa only [source 45 (by decide),Nat.reduceAdd] using small.2.2.2.2.2
  · rw [source 46 (by decide)]
    change packedWord packed 41454 < 256
    omega
  · simpa only [source 4 (by decide),source 5 (by decide),Nat.reduceAdd] using noRetirement


end HegemonCrypto.SmallWood.V8Smz9SemanticStableCanonicalEndpoint
