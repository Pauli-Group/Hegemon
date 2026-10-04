import Q38Rp05CurrentTailDefinition
import Q38Rp05CurrentCompleteProgram
import Q38ConcreteAdaptivePrivacy
import Q38Rp05ExecutionBridge

/-!
# current_complete_honest_request_full_overlay

This theorem is isolated from the request compiler to bound per-module Lean
elaboration memory. Its statement and proof are moved unchanged.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9RawCounterCompiler
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05CurrentPrefinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped Classical
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

/-- The request's actual fresh-leaf execution is the full persistent overlay
on the same corrected raw oracle. The old state is not reinitialized. -/
theorem current_complete_honest_request_full_overlay
    {bound : Nat} {Work : Type} [Fintype Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (state : GameState
      (Input := Rp05FullRawInput bound) (Work := Work)) :
    run true (currentCompleteHonestRequest largeEnough dsl statement values
      salt widthBound next) oldOracle state =
      uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            uniformAverage (fun labels : LeafIndex → DigestRegister =>
              let data := q38PhysicalSuffix
                (currentHeads values base masks.1) base.2.2 masks.2
              let keys : LeafIndex → Rp05FullRawInput bound :=
                fun index => Sum.inl (rp05SourceLeafInput statement salt
                  (data index) index (tapes index))
              let overlay := updateRp05Batch 8388608 keys labels oldOracle
              run true (currentRequestTail largeEnough dsl statement values
                salt widthBound base masks tapes labels next)
                overlay state)))) := by
  change uniformAverage (fun base : RemainingCoins Goldilocks =>
      uniformAverage (fun masks : Q × D =>
        run true
          (rp05LeafBatch 8388608 id statement salt
            (q38PhysicalSuffix
              (currentHeads values base masks.1) base.2.2 masks.2)
            (fun tapes labels => currentRequestTail largeEnough dsl statement
              values salt widthBound base masks tapes labels next))
          oldOracle state)) = _
  apply congrArg uniformAverage
  funext base
  apply congrArg uniformAverage
  funext masks
  exact rp05_leaf_batch_full_overlay_execution 8388608 id
    (fun _ _ same => same) statement salt
    (q38PhysicalSuffix (currentHeads values base masks.1)
      base.2.2 masks.2)
    (fun tapes labels => currentRequestTail largeEnough dsl statement values
      salt widthBound base masks tapes labels next)
    oldOracle state

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
