import HegemonCrypto.SmallWoodV8Smz9FinalSourceCallback
import HegemonCrypto.SmallWoodV8Smz9SourceLifetime

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
open V8Smz9CurrentPublicContext
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

/-- Forget no request data used by the source compiler. In particular the
packing values come from this admitted request's own witness. -/
def requestContext (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound) : RequestContext bound where
  largeEnough := largeEnough
  statementBinding := request.statementBinding
  bindingFits := request.bindingFits
  statement := request.statement
  values := packingValues request.witness
  salt := request.salt
  retainedRows := request.retainedRows
  rowBound := request.rowBound


/-- The false operational request is exactly the actual source request with
its current leaf events randomized. This is pointwise in the full persistent
oracle and branch state, with an arbitrary complete byte/error continuation.
No endpoint equality, independent oracle, or normalized branch is supplied. -/
theorem operational_request_false_is_complete_source
    (largeEnough : 37434 ≤ bound)
    (request : V8Smz9SourceLifetime.SourceRequestData bound)
    (next : ByteResult → V8Smz9HonestWholeViewGames.Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (state : GameState (Input := FullRawInput bound) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run false
      (operationalRequest (requestContext largeEnough request)
        (fun bytes => V8Smz9MixedMaskCompiler.fixedProgram true (next bytes))) oracle state =
    uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
      uniformAverage (fun masks : JointMaskCoins Goldilocks =>
        V8Smz9HonestWholeViewGames.run true
          (sourceCompleteByteRequest bound largeEnough request.statementBinding request.bindingFits
            request.statement (packingValues request.witness) base masks request.salt
            request.retainedRows request.rowBound next) oracle state)) := by
  rw [honest_operational_request_is_actual_randomized_leaf_source]
  apply congrArg uniformAverage
  funext base
  apply congrArg uniformAverage
  funext masks
  simpa only [requestContext] using
    source_callback_is_complete_byte_request (requestContext largeEnough request) base masks next oracle state

end
end HegemonCrypto.SmallWood.V8Smz9FinalLifetime
