import Q38Rp05CurrentTailDefinition
import Q38Rp05CurrentResultDefinition
import Q38Rp05CurrentFixedOracle
import Q38Rp05CurrentCompleteProgram
import Q38Rp05CurrentFullOverlay
import Q38ConcreteAdaptivePrivacy
import Q38Rp05ExecutionBridge

/-!
# current_complete_honest_request_result_average

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

/-- The actual current request, including its real error branches, is the
average of exact serialized results on the full persistent leaf overlay.
The continuation sees only the emitted bytes or abort, not hidden coins. -/
theorem current_complete_honest_request_result_average
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
              run true
                (next (currentRequestResult largeEnough dsl statement values
                  salt widthBound base masks tapes labels overlay))
                overlay state)))) := by
  rw [current_complete_honest_request_full_overlay]
  apply congrArg uniformAverage
  funext base
  apply congrArg uniformAverage
  funext masks
  apply congrArg uniformAverage
  funext tapes
  apply congrArg uniformAverage
  funext labels
  exact current_request_tail_fixed_oracle true largeEnough dsl statement
    values salt widthBound base masks tapes labels next _ state

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
