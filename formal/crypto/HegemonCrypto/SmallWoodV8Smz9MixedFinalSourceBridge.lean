import HegemonCrypto.SmallWoodV8Smz9MixedFinalOperational
import HegemonCrypto.SmallWoodV8Smz9BaseDependentTransport

namespace HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9CurrentPrivacyComposition V8Smz9EagerPrivacy V8Smz9EagerOracleGame
open V8Smz9HonestFinalGame V8Smz9DynamicRequest V8Smz9DynamicPhysicalTransport
open V8Smz9HonestHybrid V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule
open V8Smz9HonestWholeViewGames (GameState)
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000

variable {Work : Type} [Fintype Work] {bound : Nat}

attribute [local irreducible] V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run
  sourceAllLeavesThenComputedPrefix operationalRequest physicalOutputObservation

/-- Starting from the actual source request with randomized current leaf
events, the checked source Q/M transport gives exactly this operational
request's false game. The continuation runs the actual post-final source byte
program and retains each request's original base coins. -/
theorem honest_operational_request_is_actual_randomized_leaf_source
    (context : RequestContext bound)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run false
      (operationalRequest context (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) oracle state =
    uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
      uniformAverage (fun masks : JointMaskCoins Goldilocks =>
        V8Smz9HonestWholeViewGames.run true
          (sourceAllLeavesThenComputedPrefix bound (by have := context.largeEnough; omega)
            context.statementBinding context.bindingFits context.statement context.values base masks context.salt
            context.retainedRows context.rowBound (oldByteContinuation context base next)) oracle state)) := by
  rw [honest_request_is_transported_physical_observation]
  symm
  simpa only [transportedMasks] using
    randomized_source_prefix_physical_mask_transport_base_dependent bound
      (by have := context.largeEnough; omega) context.statementBinding context.bindingFits context.statement
      context.values context.salt context.retainedRows context.rowBound
      (fun base => oldByteContinuation context base next) oracle state


/-- The selected true game keeps its actual nonleaf final-key update beneath
every subsequent original-mask leaf write and the actual byte continuation. -/
theorem selected_final_then_actual_leaf_writes (context : RequestContext bound)
    (labels : LeafIndex → DigestRegister) (stage : PrefinalResult)
    (response : DecsFullCoefficients Goldilocks)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run true
      (selectedFinal context labels stage response (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes)))
      oracle state =
    uniformAverage (fun transcript : PiopCoefficients Goldilocks =>
      uniformAverage (fun digest : DigestRegister =>
        uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            V8Smz9HonestWholeViewGames.run true
              (oldByteContinuation context base next tapes labels stage response transcript digest (retainedPending stage))
              (actualLeafOverlay
                (Function.update oracle (sourceFinalKey bound (by have := context.largeEnough; omega)
                  (sourceDigestPrefix stage.hashFpp) transcript) digest)
                context.values base (recoveredMasks context base stage response transcript) context.salt tapes labels)
              state)))) := by
  rw [selected_final_randomized_execution]
  simp_rw [after_final_fixed_executes]


end
end HegemonCrypto.SmallWood.V8Smz9MixedFinalOperational
