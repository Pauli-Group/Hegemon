import SmzaRp05AccumulatorHashBridge
import HegemonCrypto.SmallWoodV8Smz9FullRateSponge

/-!
# Exact RP05 Final-intent fold

This file composes the thirteen accepted Poseidon2 calls at slots 81--93.
The input is the literal 104-word Final intent projection, and the first
frame uses the live source domain `0x4854_5838_494e_5401` together with the
live sponge-mode and suite markers.  The only artifact premises are the
finite CSR/source certificates and the finite Poseidon recurrence
certificate already consumed by the current RP05 acceptance theorem.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05FinalIntentFold

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex)
open V8Smz9SemanticDecoder
  (packedWord packed_word_canonical)
open V8Smz9SemanticDenseRange
  (F canonical_nat_cast_injective canonical_public_coordinate)
open V8Smz9Poseidon2TemplateRefinement
open V8Smz9SemanticPoseidonKernelBinding (packedInitialState)
open V8Smz9FullRateSponge
open SmzaRp05TypedRelation
open SmzaRp05AuthSourceBridge
open SmzaRp05AccumulatorHashBridge
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

/-- The live RP05 source constant `SMALLWOOD_POSEIDON2_V8_ACTION_INTENT_DOMAIN`.
The older semantic-specification name ending in `...5400` is deliberately not
used by this proof. -/
def currentIntentBindingDomain : Nat := 0x4854_5838_494e_5401

theorem current_intent_binding_domain_is_live :
    currentIntentBindingDomain = CurrentSpongeFamily.domain .intent := rfl

/-- One of the exact 104 public intent words consumed by calls81--93. -/
def finalIntentWord (publicWords : List Nat) (word : Fin 104) : Nat :=
  if intentForcedZero word then 0
  else publicWords.getD (intentOriginalIndex word) 0

/-- The concrete 104-word RP05 Final intent preimage. -/
def finalIntentWords (publicWords : List Nat) : List Nat :=
  List.ofFn (finalIntentWord publicWords)

@[simp] theorem final_intent_words_length (publicWords : List Nat) :
    (finalIntentWords publicWords).length = 104 := by
  simp [finalIntentWords]

theorem final_intent_words_getD (publicWords : List Nat) (word : Fin 104) :
    (finalIntentWords publicWords).getD word.val 0 = finalIntentWord publicWords word := by
  change (List.ofFn (finalIntentWord publicWords)).getD word.val 0 = _
  exact HegemonCrypto.SmallWood.SmzaRp05AccumulatorFrameLookup.ofFn_getD _ word

theorem final_intent_word_canonical
    {components : RelationProgramComponents}
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (word : Fin 104) :
    finalIntentWord publicWords word < Poseidon2V8RelationProgram.fieldModulus := by
  unfold finalIntentWord
  split
  · decide
  · exact (canonical_public_coordinate accepted.1 (index := intentOriginalIndex word) (by
      unfold intentOriginalIndex
      split_ifs <;> norm_num [Poseidon2V8RelationProgram.publicStatementWordCount]
        <;> omega)).2

/-- The rate-cell CSR equations expose precisely the concrete public intent
preimage, rather than an unconstrained seven-word digest. -/
theorem accepted_final_intent_absorbed_word
    {components : RelationProgramComponents}
    (certificate : CurrentAbsorbCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (word : Fin 104) :
    absorbedWord packed 81 word.val =
      ((finalIntentWords publicWords).getD word.val 0 : V8Smz9SemanticDenseRange.F) := by
  rw [final_intent_words_getD]
  simpa [finalIntentWord, intentTarget] using
    accepted_current_intent_word certificate accepted word

/-- State before block `block`; block zero is the all-zero sponge state and
every later state is the preceding accepted call's complete 16-word output. -/
def finalIntentState (packed : List Nat) (block : Nat) : List Nat :=
  if block = 0 then poseidon2V8InitialState
  else packedFinalState packed (81 + block - 1)

def finalIntentFrame (publicWords packed : List Nat) (block : Nat) : List Nat :=
  fullRateFrame currentIntentBindingDomain (finalIntentWords publicWords) 13
    (finalIntentState packed block) block

private theorem final_intent_packed_final_state_getD
    (packed : List Nat) (call lane : Nat) (laneBound : lane < 16) :
    (packedFinalState packed call).getD lane 0 =
      packed.getD (hashFinalIndex call lane) 0 := by
  simpa only [List.getD_eq_getElem?_getD] using
    (show (packedFinalState packed call)[lane]?.getD 0 =
        packed[hashFinalIndex call lane]?.getD 0 by
      simp only [packedFinalState, List.getElem?_map,
        List.getElem?_range laneBound, Option.map_some,
        Option.getD_some, packedWord,
        List.getD_eq_getElem?_getD])

private theorem fullRateFrame_word_canonical
    (domain : Nat) (inputs : List Nat) (blocks : Nat) (state : List Nat)
    (block lane : Nat) (laneBound : lane < 16)
    (domainBound : domain < Poseidon2V8RelationProgram.fieldModulus)
    (inputsBound : inputs.length < Poseidon2V8RelationProgram.fieldModulus)
    (stateBound : ∀ index, index < 16 →
      state.getD index 0 < Poseidon2V8RelationProgram.fieldModulus) :
    (fullRateFrame domain inputs blocks state block).getD lane 0 <
      Poseidon2V8RelationProgram.fieldModulus := by
  have modeBound : poseidon2V8SpongeModeMarker <
      Poseidon2V8RelationProgram.fieldModulus := by
    norm_num [poseidon2V8SpongeModeMarker,
      Poseidon2V8RelationProgram.fieldModulus]
  have suiteBound : poseidon2V8SuiteMarker <
      Poseidon2V8RelationProgram.fieldModulus := by
    norm_num [poseidon2V8SuiteMarker,
      Poseidon2V8RelationProgram.fieldModulus]
  unfold fullRateFrame
  simp only [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range laneBound, Option.map_some, Option.getD_some]
  split_ifs <;> first
    | exact Nat.mod_lt _ (by decide)
    | exact stateBound _ laneBound
    | exact domainBound
    | exact inputsBound
    | exact modeBound
    | exact suiteBound

/-- Every one of the 208 initial-state cells in calls81--93 is the exact live
full-rate frame cell.  Rate cells use the 104 finite absorbed-word CSR
equations; capacity cells use the finite frame CSR equations. -/
theorem accepted_final_intent_frame_word
    {components : RelationProgramComponents}
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (block lane : Nat) (blockBound : block < 13) (laneBound : lane < 16) :
    packed.getD (hashInitialIndex (81 + block) lane) 0 =
      (finalIntentFrame publicWords packed block).getD lane 0 := by
  have packedCanonical := packed_word_canonical accepted.2.1
  have expectedBound :
      (finalIntentFrame publicWords packed block).getD lane 0 <
        Poseidon2V8RelationProgram.fieldModulus := by
    have stateBound : ∀ index, index < 16 →
        (finalIntentState packed block).getD index 0 <
          Poseidon2V8RelationProgram.fieldModulus := by
      intro index indexBound
      by_cases first : block = 0
      · subst block
        norm_num [finalIntentState, poseidon2V8InitialState,
          Poseidon2V8RelationProgram.fieldModulus]
      · simp only [finalIntentState, if_neg first, packedFinalState,
          List.getD_eq_getElem?_getD, List.getElem?_map,
          List.getElem?_range indexBound, Option.map_some, Option.getD_some,
          packedWord]
        exact packedCanonical _
    have inputsBound : (finalIntentWords publicWords).length <
        Poseidon2V8RelationProgram.fieldModulus := by
      rw [final_intent_words_length]
      norm_num [Poseidon2V8RelationProgram.fieldModulus]
    have domainBound : currentIntentBindingDomain <
        Poseidon2V8RelationProgram.fieldModulus := by
      norm_num [currentIntentBindingDomain, Poseidon2V8RelationProgram.fieldModulus]
    exact fullRateFrame_word_canonical currentIntentBindingDomain
      (finalIntentWords publicWords) 13 (finalIntentState packed block)
      block lane laneBound domainBound inputsBound stateBound
  apply canonical_nat_cast_injective (packedCanonical _) expectedBound
  by_cases active : lane < 8
  · let word : Fin 104 := ⟨block * 8 + lane, by omega⟩
    have equation := accepted_final_intent_absorbed_word absorbed accepted word
    interval_cases block <;> interval_cases lane <;>
      simp only [word, finalIntentFrame, fullRateFrame] at equation ⊢
    all_goals norm_num [finalIntentState, finalIntentWord, packedFinalState,
      packedWord, absorbedWord, intentForcedZero, intentOriginalIndex,
      currentIntentBindingDomain, poseidon2V8InitialState,
      Poseidon2Width16Kernel.width, poseidon2V8SpongeModeMarker,
      poseidon2V8SuiteMarker,
      V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd] at active equation ⊢
    all_goals linear_combination equation
  · let cell : CurrentFrameWord :=
      { family := .intent
        block := block
        lane := ⟨lane, laneBound⟩
        blockBound := by
          simpa [CurrentSpongeFamily.blockCount] using blockBound
        isFrame := by
          left
          exact Nat.le_of_not_gt active }
    have equation := accepted_current_frame_word frames accepted cell
    interval_cases block <;> interval_cases lane <;>
      simp only [cell, finalIntentFrame, fullRateFrame] at equation ⊢
    all_goals norm_num [finalIntentState, finalIntentWord,
        packedFinalState, packedWord, CurrentFrameWord.difference, CurrentFrameWord.expected,
        CurrentSpongeFamily.firstCall, CurrentSpongeFamily.wordCount,
        CurrentSpongeFamily.blockCount, CurrentSpongeFamily.domain,
        currentIntentBindingDomain, spongeModeMarker, suiteMarker,
        poseidon2V8InitialState, Poseidon2Width16Kernel.width,
        poseidon2V8SpongeModeMarker, poseidon2V8SuiteMarker,
        V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd] at active equation ⊢
    all_goals linear_combination equation

theorem accepted_final_intent_initial_state
    {components : RelationProgramComponents}
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (block : Nat) (bound : block < 13) :
    packedInitialState packed (81 + block) =
      finalIntentFrame publicWords packed block := by
  apply List.ext_getElem
  · simp [packedInitialState, finalIntentFrame, fullRateFrame]
  · intro lane leftBound rightBound
    have laneBound : lane < 16 := by simpa [packedInitialState] using leftBound
    have equal := accepted_final_intent_frame_word absorbed frames accepted
      block lane bound laneBound
    simpa [packedInitialState, packedWord, List.getD_eq_getElem,
      laneBound, leftBound, rightBound] using equal

/-- Calls81--93 are the exact 13-block fold of the concrete 104-word live
intent preimage.  No digest equality occurs in the premises. -/
theorem accepted_final_intent_fold
    {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    poseidon2V8Sponge currentIntentBindingDomain (finalIntentWords publicWords) =
      (packedFinalState packed 93).take digestWords := by
  have composition := full_rate_sponge_of_frame_chain
    currentIntentBindingDomain (finalIntentWords publicWords) 13
    (finalIntentState packed) (by simp [finalIntentWords]) (by decide)
    (by simp [finalIntentState])
    (by
      intro block within
      unfold finalIntentState
      split <;> simp [poseidon2V8InitialState,
        Poseidon2Width16Kernel.width, packedFinalState])
    (by
      intro block within
      have initial := accepted_final_intent_initial_state absorbed frames accepted
        block within
      have trace := accepted_hash_call_state kernel accepted
        (call := 81 + block) (by omega)
      have frameToInitial :
          fullRateFrame currentIntentBindingDomain (finalIntentWords publicWords) 13
              (finalIntentState packed block) block =
            packedInitialState packed (81 + block) := initial.symm
      rw [frameToInitial]
      exact trace)
  simpa [finalIntentState] using composition

/-- The raw accumulator intent limb is the corresponding limb of the exact
live 104-word intent sponge.  The raw-to-call93 edge is the existing Final
selector theorem; the call93-to-sponge edge is the fold above. -/
theorem accepted_final_intent_digest_word
    {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components)
    (localCertificate : CurrentLocalArtifactCertificate components)
    (direct : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (finalSelected :
      (packedWitnessLaneRows packed 0).getD finalRow 0 = 1)
    (limb : Fin 7) :
    packed.getD (rawIndex (129 + limb.val)) 0 =
      (poseidon2V8Sponge currentIntentBindingDomain
        (finalIntentWords publicWords)).getD limb.val 0 := by
  have stored := accepted_final_intent_digest localCertificate direct accepted finalSelected limb
  have fold := accepted_final_intent_fold kernel absorbed frames accepted
  have emitted :
      (packedFinalState packed 93).getD limb.val 0 =
        (poseidon2V8Sponge currentIntentBindingDomain
          (finalIntentWords publicWords)).getD limb.val 0 := by
    have atLimb := congrArg (fun words : List Nat => words.getD limb.val 0) fold
    simpa [digestWords, List.getD_eq_getElem?_getD,
      List.getElem?_take, limb.isLt] using atLimb.symm
  have stateWord : (packedFinalState packed 93).getD limb.val 0 =
      packed.getD (hashFinalIndex 93 limb.val) 0 := by
    have laneBound : limb.val < 16 := by omega
    exact final_intent_packed_final_state_getD packed 93 limb.val laneBound
  exact stored.trans (stateWord.symm.trans emitted)

/-- Seven-limb vector form consumed by the authorization registry. -/
theorem accepted_final_intent_digest
    {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    (absorbed : CurrentAbsorbCertificate components)
    (frames : CurrentFrameCertificate components)
    (localCertificate : CurrentLocalArtifactCertificate components)
    (direct : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (finalSelected :
      (packedWitnessLaneRows packed 0).getD finalRow 0 = 1) :
    (fun limb : Fin 7 => packed.getD (rawIndex (129 + limb.val)) 0) =
      (fun limb : Fin 7 =>
        (poseidon2V8Sponge currentIntentBindingDomain
          (finalIntentWords publicWords)).getD limb.val 0) := by
  funext limb
  exact accepted_final_intent_digest_word kernel absorbed frames localCertificate direct
    accepted finalSelected limb

end
end HegemonCrypto.SmallWood.SmzaRp05FinalIntentFold
