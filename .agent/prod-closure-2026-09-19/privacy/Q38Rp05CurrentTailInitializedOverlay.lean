import Q38Rp05CurrentTailDefinition
import Q38Rp05CurrentTailPointwiseSpecialization

/-!
# Current initialized tail overlay identity

The exact current-tail theorem is isolated from the following finite-average
composition theorem so Lean can check each endpoint independently.
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
set_option maxRecDepth 100000

-- Match the checked pointwise theorem's abstract-environment dictionary.
-- This changes no finite set or uniform law.
attribute [local instance] tailLeafIndexDecidableEq

-- Average the checked pointwise execution law without reducing the
-- concrete full-tree interpreter or enumerating either finite table.
attribute [local irreducible] readCurrentAnswers updateRp05Batch
  compressedSwapList currentRequestTail liftEnvironmentProgram
  initializedPhaseFamily phaseRun uniformAverage
  V8Smz9HonestWholeViewGames.run

/-- Corrected current-profile P7 prefix: after the persistent fresh-leaf
swap, the complete current request tail runs on the 2511-byte-disjoint
overlay while retaining the unchanged old-oracle-indexed prior state. This
is the generic swap theorem instantiated on the actual current raw carrier,
not the older SMZ9 complement. -/
theorem current_request_tail_initialized_full_overlay
    {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (next : Except String (List Byte) →
      Program (Rp05FullRawInput bound) Work)
    (family : OracleRegisterFamily
      (Input := Rp05FullRawInput bound) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      phaseRun true
        (liftEnvironmentProgram
          (Environment := LeafIndex → DigestRegister)
          (readCurrentAnswers 8388608
            (fun i => (Sum.inl (rp05SourceLeafInput statement salt
              (q38PhysicalSuffix (currentHeads values base masks.1)
                base.2.2 masks.2 i) i (tapes i)) : Rp05FullRawInput bound))
            (fun labels => currentRequestTail largeEnough dsl statement values
              salt widthBound base masks tapes labels next)))
        (compressedSwapList
          (fun index => (Sum.inl (rp05SourceLeafInput statement salt
            (q38PhysicalSuffix (currentHeads values base masks.1)
              base.2.2 masks.2 index) index (tapes index)) :
                Rp05FullRawInput bound))
          (List.ofFn (id : Fin 8388608 → LeafIndex))
          (initializedPhaseFamily family))) =
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        uniformAverage
          (fun oldOracle : Rp05FullRawInput bound → DigestRegister =>
            uniformAverage (fun labels : LeafIndex → DigestRegister =>
              let keys : LeafIndex → Rp05FullRawInput bound :=
                fun index => Sum.inl (rp05SourceLeafInput statement salt
                  (q38PhysicalSuffix (currentHeads values base masks.1)
                    base.2.2 masks.2 index) index (tapes index))
              let overlay := updateRp05Batch 8388608 keys labels oldOracle
              V8Smz9HonestWholeViewGames.run true
                (currentRequestTail largeEnough dsl statement values salt
                  widthBound base masks tapes labels next)
                overlay (familyGameState family oldOracle)))) := by
  apply congrArg uniformAverage
  funext tapes
  exact current_request_tail_initialized_full_overlay_at_pointwise_aligned
    (count := 8388608) rfl (Equiv.refl LeafIndex)
    largeEnough dsl statement values salt widthBound base masks tapes next family

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
