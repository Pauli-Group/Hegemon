import HegemonCrypto.SmallWoodV8Smz9MixedFinalSourceBridge

/-! Concrete continuation transport for the operational final request. The
relation is proved for every persistent logical oracle and every branch state;
no history is discarded, normalized, or replaced by free oracle advice. -/

namespace HegemonCrypto.SmallWood.V8Smz9FinalLifetime

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9HonestHybrid
open V8Smz9DynamicPhysicalTransport V8Smz9MixedFinalOperational
open V8Smz9HonestWholeViewGames (GameState)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Work : Type} [Fintype Work] {bound : Nat}

attribute [local irreducible] V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run
  V8Smz9MixedMaskCompiler.actualLeafWrites nonleafCompile sourcePrefinal sourceFinalKey
  actualLeafOverlay postFinalBytes

theorem written_nonleaf_continuation_congr (mode : Bool)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (program : NonleafProgram (OtherRawInput bound) ByteResult)
    (left right : ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes oracle state,
      V8Smz9MixedMaskCompiler.run mode (left bytes) oracle state =
        V8Smz9MixedMaskCompiler.run mode (right bytes) oracle state)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode
      (V8Smz9MixedMaskCompiler.actualLeafWrites values base masks salt tapes labels (nonleafCompile program left))
      oracle state =
    V8Smz9MixedMaskCompiler.run mode
      (V8Smz9MixedMaskCompiler.actualLeafWrites values base masks salt tapes labels (nonleafCompile program right))
      oracle state := by
  rw [V8Smz9MixedMaskCompiler.actual_leaf_writes_execution,
    V8Smz9MixedMaskCompiler.actual_leaf_writes_execution, nonleaf_compile_executes, nonleaf_compile_executes]
  exact remaining _ _ _


theorem random_pair_continuation_congr (A B : Type) [Fintype A] [Nonempty A] [Fintype B] [Nonempty B]
    (mode : Bool) (left right : A → B → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ first second oracle state,
      V8Smz9MixedMaskCompiler.run mode (left first second) oracle state =
        V8Smz9MixedMaskCompiler.run mode (right first second) oracle state)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (randomPair A B left) oracle state =
      V8Smz9MixedMaskCompiler.run mode (randomPair A B right) oracle state := by
  rw [random_pair_execution, random_pair_execution]
  apply congrArg uniformAverage
  funext first
  apply congrArg uniformAverage
  funext second
  exact remaining first second oracle state

theorem after_final_continuation_congr (mode : Bool) (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (left right : ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes oracle state,
      V8Smz9MixedMaskCompiler.run mode (left bytes) oracle state =
        V8Smz9MixedMaskCompiler.run mode (right bytes) oracle state)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (afterFinal context labels stage response transcript digest left) oracle state =
      V8Smz9MixedMaskCompiler.run mode (afterFinal context labels stage response transcript digest right) oracle state := by
  unfold afterFinal
  apply random_pair_continuation_congr
  intro base tapes current currentState
  exact written_nonleaf_continuation_congr mode context.values base
    (recoveredMasks context base stage response transcript) context.salt tapes labels
    (postFinalBytes context base stage response transcript digest tapes) left right remaining current currentState


theorem selected_final_continuation_congr (mode : Bool) (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks)
    (left right : ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes oracle state,
      V8Smz9MixedMaskCompiler.run mode (left bytes) oracle state =
        V8Smz9MixedMaskCompiler.run mode (right bytes) oracle state)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (selectedFinal context labels stage response left) oracle state =
      V8Smz9MixedMaskCompiler.run mode (selectedFinal context labels stage response right) oracle state := by
  cases mode with
  | false =>
      simp only [selected_final_honest_execution]
      apply congrArg uniformAverage
      funext transcript
      exact after_final_continuation_congr false context labels stage response transcript _ left right remaining oracle state
  | true =>
      simp only [selected_final_randomized_execution]
      apply congrArg uniformAverage
      funext transcript
      apply congrArg uniformAverage
      funext digest
      exact after_final_continuation_congr true context labels stage response transcript digest left right remaining _ state


theorem operational_request_continuation_congr (mode : Bool) (context : RequestContext bound)
    (left right : ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes oracle state,
      V8Smz9MixedMaskCompiler.run mode (left bytes) oracle state =
        V8Smz9MixedMaskCompiler.run mode (right bytes) oracle state)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run mode (operationalRequest context left) oracle state =
      V8Smz9MixedMaskCompiler.run mode (operationalRequest context right) oracle state := by
  simp only [operational_request_executes_prefix]
  apply congrArg uniformAverage
  funext labels
  apply congrArg uniformAverage
  funext response
  exact selected_final_continuation_congr mode context labels _ response left right remaining oracle state


end
end HegemonCrypto.SmallWood.V8Smz9FinalLifetime
