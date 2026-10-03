import Q38Rp05AbortAwareOpening
import Q38Rp05PostFinalCompiler
import Q38Rp05WholePrivacy
import Q38Rp05CurrentPostfinal
import Q38Rp05LeafSupport

/-!
The selected RP05 continuation consumes only the tapes revealed by the
literal abort-aware selector.  Its serialized bytes coincide with the honest
post-final selected branch on every full tape table.
This is the compiler model from `Q38Rp05CompleteRequest`; its physical
SMZA-profile and disjoint raw-input transport obligations remain open.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05SelectedContinuation

open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9HonestFinalGame (OtherRawInput)
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport (Rp05LeafInput)
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.V8SmzaSelectionFeedback
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05FullAdaptiveComposition
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

/-- The actual chronological view at a selector result.  On exhaustion its
later coordinate is absent; on success it is the physical 38-point subset. -/
def selectedPhysicalView
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    {points : Fin 6 → Goldilocks}
    (job : SelectionResult points) : PartialView Goldilocks :=
  (sourceWitnessOpenings values points base.1,
   sourcePcsFullView points (pcsBase points q reply) base.2.1,
   earlier points base.2.2,
   job.targets.map fun targets =>
     fullSubset (currentHeads values base q) base.2.2
       (indexedPoints targets.val))

/-- Only the `Opened` tape function enters the proof bytes.  Unopened tapes
are padded with zero solely to call the existing serializer; the equality
below proves that padding is observationally irrelevant. -/
def actualSelectedContinuation
    {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (next : Except String (List Byte) →
      Program (Rp05LeafInput ⊕ OtherRawInput bound) Work)
    (job : SelectionResult opening.points)
    (visible : Opened (rp05AbortAwareUnopened job) → LeafTape) :
    Program (Rp05LeafInput ⊕ OtherRawInput bound) Work :=
  let tapes := visiblePadding (rp05AbortAwareUnopened job) visible
  next (selectedBytes dsl statement parameters opening gamma reply transcript
    digest salt tree tapes (selectedPhysicalView values base q reply job) job)

theorem selected_bytes_ignore_unopened_tapes
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (job : SelectionResult opening.points) (tapes : TapeTable) :
    selectedBytes dsl statement parameters opening gamma reply transcript
        digest salt tree tapes (selectedPhysicalView values base q reply job) job =
      selectedBytes dsl statement parameters opening gamma reply transcript
        digest salt tree
        (visiblePadding (rp05AbortAwareUnopened job)
          ((tapeSplit (rp05AbortAwareUnopened job) tapes).1))
        (selectedPhysicalView values base q reply job) job := by
  cases chosen : job.targets with
  | none => simp [selectedBytes, chosen]
  | some targets =>
      have tape_eq :
          (fun i : Fin 38 =>
            visiblePadding (rp05AbortAwareUnopened job)
              ((tapeSplit (rp05AbortAwareUnopened job) tapes).1)
              (targets.val i)) =
          (fun i : Fin 38 => tapes (targets.val i)) := by
        funext i
        have opened : targets.val i ∉ rp05AbortAwareUnopened job := by
          simp [rp05AbortAwareUnopened, chosen, q38Unopened]
        simp [visiblePadding, tapeSplit, opened]
      simp only [selectedBytes, selectedPhysicalView, chosen]
      apply congrArg (finishBytes job.pendingFailure)
      congr 1
      funext index
      exact (congrFun tape_eq index).symm

theorem actual_selected_continuation_on_real_tapes
    {bound : Nat} {Work : Type} [Fintype Work]
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (next : Except String (List Byte) →
      Program (Rp05LeafInput ⊕ OtherRawInput bound) Work)
    (job : SelectionResult opening.points) (tapes : TapeTable) :
    actualSelectedContinuation dsl statement parameters opening values base q
        gamma reply transcript digest salt tree next job
        ((tapeSplit (rp05AbortAwareUnopened job) tapes).1) =
      next (selectedBytes dsl statement parameters opening gamma reply
        transcript digest salt tree tapes
    (selectedPhysicalView values base q reply job) job) := by
  simpa only [actualSelectedContinuation] using
    congrArg next
      (selected_bytes_ignore_unopened_tapes dsl statement parameters
        opening values base q gamma reply transcript digest salt tree job tapes).symm

/-- The generic P8/P9 loss is now charged to the literal selected proof-byte
continuation, including index exhaustion.  Its only query requirement is the
actual downstream program's bound for every returned byte/error value. -/
theorem actual_selected_opening_bound_mass
    {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister))
    (next : Except String (List Byte) →
      Program (Rp05LeafInput ⊕ OtherRawInput bound) Work)
    (queries : Nat)
    (bounded : ∀ bytes, queryCount (next bytes) ≤ queries)
    (old : Rp05LeafInput → DigestRegister)
    (other : OtherRawInput bound → DigestRegister)
    (labels : LeafIndex → DigestRegister)
    (state : GameState
      (Input := Rp05LeafInput ⊕ OtherRawInput bound) (Work := Work)) :
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response dsl statement parameters
      (sourceWitnessPolynomials values base.1) q
    let program := actualSelectedContinuation dsl statement parameters opening
      values base q gamma reply transcript digest salt tree next
    |fullGame randomized
        (asSelection (selectIndices bound largeEnough opening.points
          (computed_opening_points_distinct opening) digest
          (combinationHeads dsl statement parameters opening.points transcript
            (sourceWitnessOpenings values opening.points base.1)
            (sourcePcsFullView opening.points
              (pcsBase opening.points q reply) base.2.1))
          (earlier opening.points base.2.2) opening.pendingFailure))
        rp05AbortAwareUnopened program old other labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m) state -
      publicGame randomized
        (asSelection (selectIndices bound largeEnough opening.points
          (computed_opening_points_distinct opening) digest
          (combinationHeads dsl statement parameters opening.points transcript
            (sourceWitnessOpenings values opening.points base.1)
            (sourcePcsFullView opening.points
              (pcsBase opening.points q reply) base.2.1))
          (earlier opening.points base.2.2) opening.pendingFailure))
        rp05AbortAwareUnopened program old other labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m) state| ≤
      (4 * ((exposures
        (asSelection (Other := OtherRawInput bound) (Work := Work)
          (selectIndices bound largeEnough opening.points
          (computed_opening_points_distinct opening) digest
          (combinationHeads dsl statement parameters opening.points transcript
            (sourceWitnessOpenings values opening.points base.1)
            (sourcePcsFullView opening.points
              (pcsBase opening.points q reply) base.2.1))
          (earlier opening.points base.2.2) opening.pendingFailure)) : ℝ) +
          queries) / (2 ^ 256 : ℝ)) * ‖state‖ ^ 2 := by
  apply rp05_abort_aware_opening_bound_mass bound randomized largeEnough
    opening.points (computed_opening_points_distinct opening) digest
    (combinationHeads dsl statement parameters opening.points
      (Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q)
      (sourceWitnessOpenings values opening.points base.1)
      (sourcePcsFullView opening.points
        (pcsBase opening.points q
          (V8SmzaMathPrivacy.response gamma
            (currentHeads values base q) base.2.2 m)) base.2.1))
    (earlier opening.points base.2.2) opening.pendingFailure
    (actualSelectedContinuation dsl statement parameters opening values base q
      gamma (V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m)
      (Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        (sourceWitnessPolynomials values base.1) q)
      digest salt tree next)
    old other labels statement salt
    (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
    queries (by intro job visible; exact bounded _) state

end
end HegemonCrypto.SmallWood.Q38Rp05SelectedContinuation
