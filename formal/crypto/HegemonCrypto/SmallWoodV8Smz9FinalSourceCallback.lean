import HegemonCrypto.SmallWoodV8Smz9MixedFinalSourceBridge
import HegemonCrypto.SmallWoodV8Smz9PostFinalQueryBudget

/-! Pointwise bridge from an admitted lifetime request to its operational
final-event request. The same witness supplies the packing values, and the
entire byte/error continuation, persistent oracle, and state are retained.

The callback bridge uses the actual computed-prefix execution law: its
pending bit is the retained DECS/PIOP failure flag. It does not assert that
the two callbacks agree at arbitrary, unreachable pending-bit arguments. -/

namespace HegemonCrypto.SmallWood.V8Smz9FinalLifetime

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9SemanticBinding V8Smz9HiddenLeafQrom V8Smz9HiddenPatch
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9EagerPrivacy V8Smz9EagerOracleGame V8Smz9RuntimeRandomness
open V8Smz9HonestRequestSchedule V8Smz9HonestFinalGame V8Smz9HonestHybrid
open V8Smz9DynamicRequest V8Smz9DynamicPhysicalTransport
open V8Smz9PostFinalProgram V8Smz9PostFinalQueryBudget
open V8Smz9MixedFinalOperational V8Smz9RuntimeDistribution
open V8Smz9HonestWholeViewGames (GameState)
open scoped Classical

noncomputable section
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Work : Type} [Fintype Work] {bound : Nat}

attribute [local irreducible] V8Smz9MixedMaskCompiler.run V8Smz9HonestWholeViewGames.run
  NonleafProgram.compile uniformAverage sourceAllLeavesThenComputedPrefix sourceComputedPrefix
  sourceDynamicPrefinal sourceComputedPiopTranscript sourceFinalKey actualLeafOverlay
  sourceCompleteByteRequest sourcePostFinalProgram sourcePostFinalBytesProgram
  operationalRequest oldByteContinuation postFinalBytes

/-- At the actual source callback invocation the pending bit is precisely
the flag retained in the stage. Both continuations therefore execute the
same post-final source byte program under the same physical leaf overlay. -/
theorem source_callback_is_complete_byte_request
    (context : RequestContext bound)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run true
      (sourceAllLeavesThenComputedPrefix bound (by have := context.largeEnough; omega)
        context.statementBinding context.bindingFits context.statement context.values base masks context.salt
        context.retainedRows context.rowBound (oldByteContinuation context base next)) oracle state =
    V8Smz9HonestWholeViewGames.run true
      (sourceCompleteByteRequest bound context.largeEnough context.statementBinding context.bindingFits
        context.statement context.values base masks context.salt context.retainedRows context.rowBound next)
      oracle state := by
  unfold sourceCompleteByteRequest
  rw [randomized_source_prefix_keeps_actual_leaf_overlay,
    randomized_source_prefix_keeps_actual_leaf_overlay]
  apply congrArg uniformAverage
  funext tapes
  apply congrArg uniformAverage
  funext labels
  rw [source_computed_prefix_execution, source_computed_prefix_execution]
  simp only [oldByteContinuation, postFinalBytes, retainedPending, sourcePostFinalProgram]



end
end HegemonCrypto.SmallWood.V8Smz9FinalLifetime
