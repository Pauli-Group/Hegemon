import HegemonCrypto.SmallWoodV8Smz9StableCounterEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem admitted_stable_public_counters {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    publicWords.getD 83 0 = statement.stablecoin.direction.word ∧
    publicWords.getD 86 0 = statement.stablecoin.magnitude ∧
    publicWords.getD 94 0 = statement.stablecoin.parentHeight ∧
    publicWords.getD 109 0 = statement.stablecoin.after.epochId ∧
    publicWords.getD 110 0 = statement.stablecoin.after.mintedInEpoch ∧
    publicWords.getD 111 0 = statement.stablecoin.after.totalDebt ∧
    publicWords.getD 112 0 = statement.stablecoin.after.sequence := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, intent, before, after, _⟩ := domain.2.1
  have encoded (word : Nat) : publicWords.getD (83 + word) 0 =
      (encodeStablecoinPublic statement.stablecoin).getD word 0 := by
    rw [← domain.1]
    exact encoded_stable_public_word statement domain.2.1 word
  have direction := encoded 0
  have magnitude := encoded 3
  have height := encoded 11
  have epoch := encoded 26
  have minted := encoded 27
  have debt := encoded 28
  have sequence := encoded 29
  simp only [encodeStablecoinPublic, List.getD_eq_getElem?_getD, List.getElem?_append,
    List.length_append, List.length_cons, List.length_nil, intent.1, before.1, after.1,
    digestWords] at direction magnitude height epoch minted debt sequence
  exact ⟨by simpa using direction, by simpa using magnitude, by simpa using height,
    by simpa using epoch, by simpa using minted, by simpa using debt, by simpa using sequence⟩

/-- The projected accepted witness satisfies all exact enabled counter relations. -/
theorem admitted_stable_counter_transition {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (isMint : Bool) (direction : statement.stablecoin.direction = if isMint then .mint else .burn) :
    let before := decodeV8StablecoinBefore (projectTypedWitness statement packed).stablecoin
    let currentEpoch := statement.stablecoin.parentHeight / (2 ^ stablecoinV8EpochHeightShift)
    let mintBase := if before.epochId = currentEpoch then before.mintedInEpoch else 0
    before.epochId ≤ currentEpoch ∧
    statement.stablecoin.after.epochId = currentEpoch ∧
    statement.stablecoin.after.mintedInEpoch = mintBase + (if isMint then statement.stablecoin.magnitude else 0) ∧
    (if isMint then statement.stablecoin.after.totalDebt = before.totalDebt + statement.stablecoin.magnitude
      else statement.stablecoin.magnitude ≤ before.totalDebt ∧
        statement.stablecoin.after.totalDebt = before.totalDebt - statement.stablecoin.magnitude) ∧
    statement.stablecoin.after.sequence = before.sequence + 1 := by
  obtain ⟨d, mag, height, epoch, minted, debt, sequence⟩ := admitted_stable_public_counters domain
  have rawDirection : publicWords.getD 83 0 = if isMint then 1 else 2 := by
    rw [d, direction]
    cases isMint <;> rfl
  have result := accepted_stable_counter_transition domain.2.2 isMint rawDirection
  have b0 := admitted_stable_before_word_source domain (counter := 0) (by decide)
  have b1 := admitted_stable_before_word_source domain (counter := 1) (by decide)
  have b2 := admitted_stable_before_word_source domain (counter := 2) (by decide)
  have b3 := admitted_stable_before_word_source domain (counter := 3) (by decide)
  dsimp only at result ⊢
  simpa only [decodeV8StablecoinBefore, b0, b1, b2, b3, mag, height, epoch, minted, debt,
    sequence, stablecoinV8EpochHeightShift, Nat.reduceAdd, Nat.reducePow] using result


end HegemonCrypto.SmallWood.V8Smz9SemanticStableTypedCounterEndpoint
