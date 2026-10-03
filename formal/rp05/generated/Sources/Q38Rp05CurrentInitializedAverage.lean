import Q38Rp05CurrentTailInitializedOverlay
import Q38Rp05CurrentCompleteProgram
import Q38Rp05CurrentFullOverlay
/-!
# Current initialized-request overlay identities

This module separates the final current-request overlay composition from the
request compiler and fixed-oracle execution facts. The theorem statements and
proofs are unchanged; the split bounds per-module Lean elaboration memory.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
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
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
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

-- Reuse the exact finite-index dictionary of the checked tail overlay.
attribute [local instance] tailLeafIndexDecidableEq
attribute [local irreducible] readCurrentAnswers updateRp05Batch
  compressedSwapList currentRequestTail liftEnvironmentProgram
  initializedPhaseFamily phaseRun uniformAverage
  V8Smz9HonestWholeViewGames.run

private theorem initialized_average_congr_instances
    {A : Type} (leftFinite rightFinite : Fintype A)
    (leftNonempty rightNonempty : Nonempty A) (left right : A → ℝ)
    (pointwise : ∀ value, left value = right value) :
    @uniformAverage A leftFinite leftNonempty left =
      @uniformAverage A rightFinite rightNonempty right := by
  have finiteEq : leftFinite = rightFinite := Subsingleton.elim _ _
  subst rightFinite
  have functionEq : left = right := funext pointwise
  subst right
  rfl

/-- The corrected initialized P7 prefix, averaged over the literal source
coins, is the entire current request on the unchanged old-oracle-indexed
family. Finite Fubini reorders only independent base/Q/D coins, tapes, old
oracle and fresh labels; it never canonicalizes a tape-dependent new state. -/
theorem current_initialized_request_oracle_average
    {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (family : OracleRegisterFamily
      (Input := Rp05FullRawInput bound) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    uniformAverage (fun base : RemainingCoins Goldilocks =>
      uniformAverage (fun masks : Q × D =>
        uniformAverage (fun tapes : LeafIndex → LeafTape =>
          phaseRun true
            (liftEnvironmentProgram
              (Environment := LeafIndex → DigestRegister)
              (readCurrentAnswers 8388608
                (fun i => (Sum.inl (rp05SourceLeafInput statement salt
                  (q38PhysicalSuffix (currentHeads values base masks.1)
                    base.2.2 masks.2 i) i (tapes i)) : Rp05FullRawInput bound))
                (fun labels => currentRequestTail largeEnough dsl statement
                  values salt widthBound base masks tapes labels next)))
            (compressedSwapList
              (fun index => (Sum.inl (rp05SourceLeafInput statement salt
                (q38PhysicalSuffix (currentHeads values base masks.1)
                  base.2.2 masks.2 index) index (tapes index)) :
                    Rp05FullRawInput bound))
              (List.ofFn (id : Fin 8388608 → LeafIndex))
              (initializedPhaseFamily family))))) =
      uniformAverage
        (fun oldOracle : Rp05FullRawInput bound → DigestRegister =>
          V8Smz9HonestWholeViewGames.run true
            (currentCompleteHonestRequest largeEnough dsl statement values
              salt widthBound next)
            oldOracle (familyGameState family oldOracle)) := by
  let f := fun (base : RemainingCoins Goldilocks) (masks : Q × D)
      (tapes : LeafIndex → LeafTape)
      (oldOracle : Rp05FullRawInput bound → DigestRegister)
      (labels : LeafIndex → DigestRegister) =>
        let data := q38PhysicalSuffix
          (currentHeads values base masks.1) base.2.2 masks.2
        let keys : LeafIndex → Rp05FullRawInput bound :=
          fun index => Sum.inl (rp05SourceLeafInput statement salt
            (data index) index (tapes index))
        let overlay := updateRp05Batch 8388608 keys labels oldOracle
        V8Smz9HonestWholeViewGames.run true
          (currentRequestTail largeEnough dsl statement values salt
            widthBound base masks tapes labels next)
          overlay (familyGameState family oldOracle)
  calc
    _ = uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            uniformAverage
              (fun oldOracle : Rp05FullRawInput bound → DigestRegister =>
                uniformAverage (fun labels : LeafIndex → DigestRegister =>
                  f base masks tapes oldOracle labels))))) := by
          apply congrArg uniformAverage
          funext base
          apply congrArg uniformAverage
          funext masks
          simpa only [f] using current_request_tail_initialized_full_overlay
            largeEnough dsl statement values salt widthBound base masks next
            family
    _ = uniformAverage
        (fun oldOracle : Rp05FullRawInput bound → DigestRegister =>
          uniformAverage (fun base : RemainingCoins Goldilocks =>
            uniformAverage (fun masks : Q × D =>
              uniformAverage (fun tapes : LeafIndex → LeafTape =>
                uniformAverage (fun labels : LeafIndex → DigestRegister =>
                  f base masks tapes oldOracle labels))))) := by
          calc
            _ = uniformAverage (fun base : RemainingCoins Goldilocks =>
                uniformAverage
                  (fun oldOracle : Rp05FullRawInput bound → DigestRegister =>
                    uniformAverage (fun masks : Q × D =>
                      uniformAverage (fun tapes : LeafIndex → LeafTape =>
                        uniformAverage (fun labels : LeafIndex → DigestRegister =>
                          f base masks tapes oldOracle labels))))) := by
                    apply congrArg uniformAverage
                    funext base
                    calc
                      _ = uniformAverage (fun masks : Q × D =>
                            uniformAverage
                              (fun oldOracle : Rp05FullRawInput bound → DigestRegister =>
                                uniformAverage (fun tapes : LeafIndex → LeafTape =>
                                  uniformAverage (fun labels : LeafIndex → DigestRegister =>
                                    f base masks tapes oldOracle labels)))) := by
                              apply congrArg uniformAverage
                              funext masks
                              exact V8Smz9CurrentPrivacyComposition.uniform_average_comm _
                      _ = _ := V8Smz9CurrentPrivacyComposition.uniform_average_comm _
            _ = _ := V8Smz9CurrentPrivacyComposition.uniform_average_comm _
    _ = _ := by
          apply congrArg uniformAverage
          funext oldOracle
          refine Eq.trans ?_ (current_complete_honest_request_full_overlay largeEnough dsl
            statement values salt widthBound next oldOracle
            (familyGameState family oldOracle)).symm
          apply initialized_average_congr_instances
          intro base
          apply initialized_average_congr_instances
          intro masks
          apply initialized_average_congr_instances
          intro tapes
          apply initialized_average_congr_instances
          intro labels
          rfl


end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
