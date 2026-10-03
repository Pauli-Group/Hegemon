import HegemonCrypto.SmallWoodV8Smz9MixedFinalCore
namespace HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9DynamicRequest
open V8Smz9HonestHybrid V8Smz9HonestOpeningSchedule
open V8Smz9DynamicTransport V8Smz9DynamicPhysicalTransport V8Smz9PostFinalProgram
open V8Smz9CurrentPublicContext V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution
open V8Smz9HonestWholeViewGames (GameState RandomSource)
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped Classical ENNReal

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000

variable {Work : Type} [Fintype Work] {bound : Nat}

attribute [local irreducible] sourcePrefinal nonleafCompile sourcePostFinalBytesProgram
  sourcePublicPostFinalBytes actualLeafOverlay V8Smz9MixedMaskCompiler.actualLeafWrites
  V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run NonleafProgram.compile oldByteContinuation



theorem after_final_fixed_executes (randomized : Bool) (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run randomized
      (afterFinal context labels stage response transcript digest
        (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) oracle state =
    uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        V8Smz9HonestWholeViewGames.run true
          (oldByteContinuation context base next tapes labels stage response transcript digest (retainedPending stage))
          (actualLeafOverlay oracle context.values base (recoveredMasks context base stage response transcript)
            context.salt tapes labels) state)) := by
  rw [afterFinal, random_pair_execution]
  apply congrArg uniformAverage
  funext base
  apply congrArg uniformAverage
  funext tapes
  simpa only [oldByteContinuation] using written_nonleaf_fixed_execution randomized context.values base
    (recoveredMasks context base stage response transcript) context.salt tapes labels
    (postFinalBytes context base stage response transcript digest tapes) next oracle state


theorem after_final_mass (cap : ℝ≥0∞) (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.InputMassAtMost cap (next bytes)) :
    V8Smz9MixedMaskCompiler.InputMassAtMost cap
      (afterFinal context labels stage response transcript digest next) := by
  unfold afterFinal
  apply random_pair_mass
  intro base tapes
  exact V8Smz9MixedMaskCompiler.actual_leaf_writes_input_mass _ _ _ _ _ _ _ _
    (nonleaf_compile_mass cap _ next remaining)


theorem after_final_program_bound (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks) (transcript : PiopCoefficients Goldilocks)
    (digest : DigestRegister) (next : ByteResult → MixedProgram (FullRawInput bound) Work)
    (programs : Nat) (remaining : ∀ bytes, V8Smz9MixedMaskCompiler.programmingCount (next bytes) ≤ programs) :
    V8Smz9MixedMaskCompiler.programmingCount
      (afterFinal context labels stage response transcript digest next) ≤ programs := by
  unfold afterFinal
  apply random_pair_program_bound
  intro base tapes
  rw [V8Smz9MixedMaskCompiler.actual_leaf_writes_programming_count]
  exact nonleaf_compile_program_bound _ next programs remaining


end
end HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational
