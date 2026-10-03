import SmzaRp05SingleKeyPrfKernel
import SmzaRp05LiveAuthorizationIdentity

/-! Accepted RP05 SingleKey witnesses bind their seven legacy words to the
source-live call-0 sponge over the five global-key words. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfKernel
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCertificate
  (accepted_call0_global_key_word)
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData
open HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule (spongePreparedWords)
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding

set_option autoImplicit false

def acceptedGlobalKey (packed : List Nat) : Fin 5 → Nat :=
  fun limb => packed.getD (227 * 64 + limb.val) 0

private theorem initialExpected_canonical (lane : Fin 16) :
    initialExpected lane <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
  fin_cases lane <;> norm_num [initialExpected,
    Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus,
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]

private theorem accepted_initial_word_nat
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (lane : Fin 16) :
    packed.getD (hashInitialIndex 0 lane.val) 0 =
      if keyLane : lane.val < 5 then
        acceptedGlobalKey packed ⟨lane.val, keyLane⟩
      else if lane.val < 8 then 0 else initialExpected lane := by
  by_cases keyLane : lane.val < 5
  · simpa [keyLane, acceptedGlobalKey] using
      accepted_call0_global_key_word accepted ⟨lane.val, keyLane⟩
  · have frame := accepted_single_key_prf_initial_frame accepted lane
    by_cases padLane : lane.val < 8
    · have fieldEquality :
          (packed.getD (hashInitialIndex 0 lane.val) 0 : Goldilocks) = 0 := by
        simpa [keyLane, padLane] using frame
      have packedBound := packed_word_canonical accepted.2.1
        (hashInitialIndex 0 lane.val)
      have zeroNat : packed.getD (hashInitialIndex 0 lane.val) 0 = 0 :=
        canonical_nat_cast_injective packedBound
          (by norm_num [Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus])
          fieldEquality
      simpa [keyLane, padLane] using zeroNat
    · have fieldEquality :
          (packed.getD (hashInitialIndex 0 lane.val) 0 : Goldilocks) =
            (initialExpected lane : Goldilocks) := by
        simpa [keyLane, padLane] using frame
      have packedBound := packed_word_canonical accepted.2.1
        (hashInitialIndex 0 lane.val)
      have expectedNat : packed.getD (hashInitialIndex 0 lane.val) 0 =
          initialExpected lane :=
        canonical_nat_cast_injective packedBound
          (initialExpected_canonical lane) fieldEquality
      simpa [keyLane, padLane] using expectedNat

private theorem source_initial_word
    (key : Fin 5 → Nat)
    (keyCanonical : ∀ limb, key limb <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus)
    (lane : Fin 16) :
    (currentSingleCall0Frame key).getD lane.val 0 =
      if keyLane : lane.val < 5 then key ⟨lane.val, keyLane⟩
      else if lane.val < 8 then 0 else initialExpected lane := by
  have keyMod (limb : Fin 5) :
      key limb % Poseidon2Width16Kernel.fieldModulus = key limb := by
    apply Nat.mod_eq_of_lt
    simpa [Poseidon2Width16Kernel.fieldModulus,
      Hegemon.Transaction.NoteCommitmentInputs.fieldModulus,
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus] using
      keyCanonical limb
  fin_cases lane <;>
    simp [currentSingleCall0Frame, currentSingleKeyWords, spongePreparedWords,
      poseidon2V8SeedFirstBlock, poseidon2V8InitialState,
      poseidon2V8SpongeModeMarker, poseidon2V8SuiteMarker,
      Poseidon2Width16Kernel.fieldAdd, Poseidon2Width16Kernel.rate,
      Poseidon2Width16Kernel.width, currentSingleKeyDomain, initialExpected,
      List.range_succ] <;>
    first | exact keyMod _ | norm_num [Poseidon2Width16Kernel.fieldModulus,
      Hegemon.Transaction.NoteCommitmentInputs.fieldModulus]

/-- The complete sixteen-word packed call-0 state is exactly the semantic
single-block sponge frame, including the five key words, two zero words,
padding, source domain, input length, mode marker, and suite marker. -/
theorem accepted_call0_initial_frame_eq
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) :
    packedInitialState packed 0 =
      currentSingleCall0Frame (acceptedGlobalKey packed) := by
  have keyCanonical : ∀ limb, acceptedGlobalKey packed limb <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
    intro limb
    exact packed_word_canonical accepted.2.1 (227 * 64 + limb.val)
  apply List.ext_getElem
  · simp only [packedInitialState, List.length_map, List.length_range]
    change 16 = (spongePreparedWords currentSingleKeyDomain
      (currentSingleKeyWords (acceptedGlobalKey packed)) 1
      poseidon2V8InitialState 0).length
    symm
    exact HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule.sponge_prepared_shape currentSingleKeyDomain
      (currentSingleKeyWords (acceptedGlobalKey packed)) 1
      poseidon2V8InitialState 0
      (by simp [poseidon2V8InitialState, Poseidon2Width16Kernel.width])
  · intro lane leftBound rightBound
    have laneBound : lane < 16 := by
      simpa [packedInitialState] using leftBound
    let stateLane : Fin 16 := ⟨lane, laneBound⟩
    have packedWordEq := accepted_initial_word_nat accepted stateLane
    have sourceWordEq := source_initial_word (acceptedGlobalKey packed)
      keyCanonical stateLane
    have joined :
        packed.getD (hashInitialIndex 0 lane) 0 =
          (currentSingleCall0Frame (acceptedGlobalKey packed)).getD lane 0 := by
      exact packedWordEq.trans sourceWordEq.symm
    rw [List.getD_eq_getElem _ _ rightBound] at joined
    simpa [packedInitialState, packedWord, List.getElem_map,
      List.getElem_range] using joined

/-- Every legacy call-0 auth word is the corresponding word of the exact
source-live semantic SingleKey sponge digest over the five global-key words. -/
theorem accepted_legacy_words_eq_semantic_single_key_digest
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (limb : Fin 7) :
    packed.getD (106 * 64 + limb.val) 0 =
      (LiveAuthorizationInput.digest
        (.singleKey (acceptedGlobalKey packed))).getD limb.val 0 := by
  let key := acceptedGlobalKey packed
  have initial := accepted_call0_initial_frame_eq accepted
  have legacy := accepted_single_key_prf_digest_word accepted limb
  have sponge := current_single_call0_frame_digest key
  have semanticWord :
      (LiveAuthorizationInput.digest (.singleKey key)).getD limb.val 0 =
        (Poseidon2Width16Kernel.permutation
          (currentSingleCall0Frame key)).getD limb.val 0 := by
    have projected := congrArg (fun digest : List Nat => digest.getD limb.val 0)
      sponge
    have taken :
        ((Poseidon2Width16Kernel.permutation
          (currentSingleCall0Frame key)).take digestWords).getD limb.val 0 =
          (Poseidon2Width16Kernel.permutation
            (currentSingleCall0Frame key)).getD limb.val 0 := by
      simp only [List.getD_eq_getElem?_getD,
        List.getElem?_take_of_lt (by change limb.val < 7; omega :
          limb.val < digestWords)]
    rw [taken] at projected
    simpa [LiveAuthorizationInput.digest] using projected
  calc
    packed.getD (106 * 64 + limb.val) 0 =
        (Poseidon2Width16Kernel.permutation (packedInitialState packed 0)).getD
          limb.val 0 := legacy
    _ = (Poseidon2Width16Kernel.permutation
          (currentSingleCall0Frame key)).getD limb.val 0 := by rw [initial]
    _ = (LiveAuthorizationInput.digest (.singleKey key)).getD limb.val 0 :=
      semanticWord.symm

end HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity
