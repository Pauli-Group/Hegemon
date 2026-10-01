import Q38Rp05CurrentAdaptiveOpening
import Q38Rp05WholePrivacy
import Q38Rp05MaskRecovery
import Q38Rp05OpenedOverlay
import SmzaRp05CurrentCoset406

/-!
# Current-profile fixed-oracle P10 opening transport

The q38 algebraic change of coordinates accepts a public-branch-dependent
selector. Here that selector is obtained by interpreting the actual SMZA
opening and fixed-index read program on the same corrected nonleaf oracle.
This is a fixed-oracle algebraic component. The full measured request and
adaptive-history probability composition remain separate obligations.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentP10

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch (LeafIndex)
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9HonestRequestSchedule
open HegemonCrypto.SmallWood.V8Smz9HonestOpeningSchedule
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame (SaltBytes)
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding (physicalHeads)
open HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy (lvcsPublicCombinationHeads)
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid (q38Unopened)
open HegemonCrypto.SmallWood.V8Smz9AdjacentComposition
open HegemonCrypto.SmallWood.V8Smz9PostFinalProgram
open HegemonCrypto.SmallWood.V8Smz9PrivacyGameComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05CurrentPostfinal
open HegemonCrypto.SmallWood.Q38Rp05CurrentAdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.Q38Rp05SelectedContinuation
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05MaskRecovery
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy (updateRp05Batch)
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport (rp05SourceLeafInput)
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

private def currentP10PhysicalHeads
    (values : WitnessPackingValues Goldilocks)
    (witness : WitnessInterpolationCoins Goldilocks)
    (masks : Q) (pcs : SourcePcsCoins Goldilocks) : Heads Goldilocks := by
  simpa only [V8SmzaMathPrivacy.Heads,
    HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy.LvcsCommittedHeads,
    V8Smz9ZeroKnowledge.lvcsRowCount,
    V8Smz9ZeroKnowledge.proofGeometryColumns,
    Hegemon.Transaction.Poseidon2V8ConstraintRefinement.proofGeometryColumnCount] using
      (physicalHeads (sourceWitnessPolynomials values witness) masks pcs)

private theorem currentP10PhysicalHeads_eq
    (values : WitnessPackingValues Goldilocks)
    (witness : WitnessInterpolationCoins Goldilocks)
    (masks : Q) (pcs : SourcePcsCoins Goldilocks) :
    currentP10PhysicalHeads values witness masks pcs =
      physicalHeads (sourceWitnessPolynomials values witness) masks pcs := by
  simp only [currentP10PhysicalHeads, id_eq]

/-- Public name for the view-facing P10 heads map used by downstream
recorded-view transports. Its definition is exactly the private P10 map. -/
def currentPhysicalHeadsView
    (values : WitnessPackingValues Goldilocks)
    (witness : WitnessInterpolationCoins Goldilocks)
    (masks : Q) (pcs : SourcePcsCoins Goldilocks) : Heads Goldilocks :=
  currentP10PhysicalHeads values witness masks pcs

private theorem current_indexed_point_eq_evaluationPoint
    (index : LeafIndex) :
    HegemonCrypto.SmallWood.Q38Rp05CurrentDisjointCoset.indexedPoint index =
      HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint index := by
  have evaluation :=
    HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.source_field_point_is_current
      (⟨index.val, by
        simp [HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.domainSize]⟩ :
        Fin HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.domainSize)
  have indexed :=
    HegemonCrypto.SmallWood.Q38Rp05CurrentDisjointCoset.current_field_point_exact index
  exact Option.some.inj (indexed.symm.trans evaluation)

private theorem current_indexed_points_eq_evaluationPoint
    (indices : Fin 38 → LeafIndex) :
    Q38Rp05PostFinalCompiler.indexedPoints indices =
      fun index => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
        (indices index) := by
  funext index
  exact current_indexed_point_eq_evaluationPoint (indices index)

/-- The q38 target choice uses exactly the current SMZA read schedule at a
fixed physical oracle, including the index-exhaustion result. -/
def currentChooseTargets
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (transcript : Q)
    (digest : DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    WitnessOpeningView Goldilocks → SourcePcsView Goldilocks →
      Earlier Goldilocks → Option (Targets opening.points) :=
  fun witness pcs early =>
    ((NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript
          witness pcs) early opening.pendingFailure)).targets).map targetValues

/-- At a fixed oracle, the public q38 view equals the view constructed from
the selector result already obtained by the physical game. The RHS does no
oracle read; it handles index exhaustion through the same `none` result. -/
theorem current_partial_view_eq_recorded_result
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    (transcript : Q) (digest : DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    let witness := sourceWitnessOpenings values opening.points base.1
    let pcs := sourcePcsFullView opening.points
      (pcsBase opening.points q reply) base.2.1
    let early := earlier opening.points base.2.2
    let result := NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript
          witness pcs) early opening.pendingFailure)
    partialChronologicalView values opening.points
        (fun _ => pcsBase opening.points q reply)
        (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
        (currentChooseTargets bound largeEnough dsl statement parameters opening
          transcript digest oracle) base =
      selectedPhysicalView values base q reply result := by
  let witness := sourceWitnessOpenings values opening.points base.1
  let pcs := sourcePcsFullView opening.points
    (pcsBase opening.points q reply) base.2.1
  let early := earlier opening.points base.2.2
  let result := NonleafProgram.interpret oracle
    (currentSelectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript
        witness pcs) early opening.pendingFailure)
  change (witness, pcs, early,
      (result.targets.map targetValues).map
        (fun targets => fullSubset (currentHeads values base q) base.2.2
          targets.val)) =
    (witness, pcs, early,
      result.targets.map fun targets =>
        fullSubset (currentHeads values base q) base.2.2
          (indexedPoints targets.val))
  cases result.targets <;> rfl

/-- Under actual accepted current-DSL constraints, the corrected SMZA index
selector consumes the public physical combination heads, not a separate
oracle-dependent advice table. Its nonce and index abort behavior is not
altered by this pointwise head equality. -/
theorem current_literal_selector_uses_physical_heads
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks)
    (q : Q) (digest : DigestRegister)
    (early : Earlier Goldilocks) (pending : Bool)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough points
        admissible.openingPointsInjective digest
        (combinationHeads
          (normalizedDsl components nonlinearRoot nodeDegree)
          statement parameters points
          (Q38Rp05ChronologicalAlgebra.response
            (normalizedDsl components nonlinearRoot nodeDegree)
            statement parameters (sourceWitnessPolynomials values base.1) q)
          (sourceWitnessOpenings values points base.1)
          (sourcePcsFullView points (pcsBase points q 0) base.2.1))
        early pending) =
    NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough points
        admissible.openingPointsInjective digest
        (lvcsPublicCombinationHeads points (currentHeads values base q))
        early pending) := by
  rw [rp05_accepted_combination_heads_are_physical components nonlinearRoot
    nodeDegree certificates statement parameters points admissible values
    base.1 q base.2.1 accepted]
  rfl

/-- On an accepted current witness, a successful corrected SMZA selector
puts the actual selected physical rows in the public chronological view.
This retains the real selected-index result and makes no oracle-alignment
assumption about a later game. -/
theorem current_successful_partial_view_is_physical
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    (digest : DigestRegister)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (selected : IndexedTargets opening.points)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values))
    (chosen : (NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
        (earlier opening.points base.2.2) opening.pendingFailure)).targets =
          some selected) :
    let transcript := Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters (sourceWitnessPolynomials values base.1) q
    let view := partialChronologicalView values opening.points
      (fun _ => pcsBase opening.points q reply)
      (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
      (currentChooseTargets bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters opening transcript digest oracle) base
    view =
      (sourceWitnessOpenings values opening.points base.1,
       sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1,
       earlier opening.points base.2.2,
       some (fullSubset (currentHeads values base q) base.2.2
         (indexedPoints selected.val))) := by
  have selectorEq := current_literal_selector_uses_physical_heads
    components nonlinearRoot nodeDegree certificates bound largeEnough
    statement parameters
    opening.points (computed_opening_interpolation_admissible opening)
    values base q digest (earlier opening.points base.2.2)
    opening.pendingFailure oracle accepted
  have chosenSource := chosen
  rw [← selectorEq] at chosenSource
  dsimp [partialChronologicalView,
    V8SmzaMathPrivacy.exactLvcsPartialFeedbackOutput, currentChooseTargets]
  rw [show pcsBase opening.points q reply = pcsBase opening.points q 0 from rfl]
  rw [chosenSource]
  rfl

/-- Construct the public 38-write oracle from a selector result already
measured by the game. This performs no oracle read of its own. -/
def currentPublicOpenedOracleFromResult
    (bound : Nat)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (result : SelectionResult opening.points)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    Rp05FullRawInput bound → DigestRegister :=
  match result.targets, view.2.2.2 with
  | some _, some later =>
    let selected := selectedIndices result
    let heads := combinationHeads dsl statement parameters opening.points
      transcript view.1 view.2.1
    let targets := fun i =>
      HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint (selected i)
    let data := q38SelectedPublicData selected
          (q38PublicSuffix opening.points
        (computed_opening_selected_rank opening) gamma reply
        heads view.2.2.1 targets later)
    updateRp05Batch 38
      (fun i => Sum.inl (rp05SourceLeafInput statement salt
        (data (selected i)) (selected i) (tapes (selected i))))
      (fun i => labels (selected i)) oldOracle
  | _, _ => oldOracle

/-- The complete no-read post-final outcome. A nonce failure has no opening
points or selector result; a successful nonce trial carries the one selector
outcome already measured by the physical game. -/
inductive CurrentRecordedPostFinal where
  | nonceAbort : CurrentRecordedPostFinal
  | opened (opening : ComputedOpening)
      (result : SelectionResult opening.points) : CurrentRecordedPostFinal

/-- Public P10 overlay from the recorded post-final outcome only. Neither
constructor makes an oracle read. The failed nonce and failed index paths
both keep the old physical oracle unchanged. -/
def currentPublicOpenedOracleFromRecorded
    (bound : Nat)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (recorded : CurrentRecordedPostFinal)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    Rp05FullRawInput bound → DigestRegister :=
  match recorded with
  | .nonceAbort => oldOracle
  | .opened opening result =>
      currentPublicOpenedOracleFromResult bound dsl statement parameters
        opening gamma reply transcript salt tapes labels view result oldOracle

theorem current_recorded_postfinal_nonce_abort_no_write
    (bound : Nat) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    currentPublicOpenedOracleFromRecorded bound dsl statement parameters
      gamma reply transcript salt tapes labels view .nonceAbort oldOracle =
        oldOracle := rfl

theorem current_recorded_postfinal_index_abort_no_write
    (bound : Nat) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (opening : ComputedOpening)
    (result : SelectionResult opening.points)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (abort : result.targets = none) :
    currentPublicOpenedOracleFromRecorded bound dsl statement parameters
      gamma reply transcript salt tapes labels view (.opened opening result)
      oldOracle = oldOracle := by
  simp [currentPublicOpenedOracleFromRecorded,
    currentPublicOpenedOracleFromResult, abort]

theorem current_public_from_result_index_abort
    (bound : Nat) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (result : SelectionResult opening.points)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (abort : result.targets = none) :
    currentPublicOpenedOracleFromResult bound dsl statement parameters opening
      gamma reply transcript salt tapes labels view result oldOracle =
      oldOracle := by
  simp [currentPublicOpenedOracleFromResult, abort]

theorem current_public_from_result_later_abort
    (bound : Nat) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (result : SelectionResult opening.points)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (abort : view.2.2.2 = none) :
    currentPublicOpenedOracleFromResult bound dsl statement parameters opening
      gamma reply transcript salt tapes labels view result oldOracle =
      oldOracle := by
  simp [currentPublicOpenedOracleFromResult, abort]

/-- The fixed-oracle P10 adapter obtains the same already-determined result
from the current selector. Neither nonce nor index exhaustion creates a
dummy leaf write; the physical game uses `...FromResult` directly. -/
def currentPublicOpenedOracle
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    Rp05FullRawInput bound → DigestRegister :=
  let otherOracle := fun input => oldOracle (Sum.inr input)
  match certifyOpening (NonleafProgram.interpret otherOracle
      (rp05ChooseOpening bound (by omega) digest pending)) with
  | none => oldOracle
  | some opening =>
    let heads := combinationHeads dsl statement parameters opening.points
      transcript view.1 view.2.1
    let result := NonleafProgram.interpret otherOracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest heads
        view.2.2.1 opening.pendingFailure)
    currentPublicOpenedOracleFromResult bound dsl statement parameters
      opening gamma reply transcript salt tapes labels view result oldOracle

theorem current_public_opened_oracle_uses_recorded_result
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opening : ComputedOpening)
    (opened : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by omega) digest pending)) = some opening) :
    let heads := combinationHeads dsl statement parameters opening.points
      transcript view.1 view.2.1
    let result := NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest heads
        view.2.2.1 opening.pendingFailure)
    currentPublicOpenedOracle bound largeEnough dsl statement parameters gamma
        reply transcript digest pending salt tapes labels view oldOracle =
      currentPublicOpenedOracleFromResult bound dsl statement parameters
        opening gamma reply transcript salt tapes labels view result oldOracle := by
  simp [currentPublicOpenedOracle, opened]

theorem current_public_opened_oracle_nonce_abort
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (abort : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by omega) digest pending)) = none) :
    currentPublicOpenedOracle bound largeEnough dsl statement parameters gamma
      reply transcript digest pending salt tapes labels view oldOracle =
      oldOracle := by
  simp [currentPublicOpenedOracle, abort]

theorem current_public_opened_oracle_index_abort
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opening : ComputedOpening)
    (opened : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by omega) digest pending)) = some opening)
    (abort : (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript
          view.1 view.2.1)
        view.2.2.1 opening.pendingFailure)).targets = none) :
    currentPublicOpenedOracle bound largeEnough dsl statement parameters gamma
      reply transcript digest pending salt tapes labels view oldOracle =
      oldOracle := by
  simp [currentPublicOpenedOracle, currentPublicOpenedOracleFromResult,
    opened, abort]

private def currentP10SelectedBatchInputs
    (bound : Nat) (statement : Statement) (salt : SaltBytes)
    (opening : ComputedOpening) (gamma : Gamma Goldilocks) (reply : D)
    (heads : PublicCombinationHeads Goldilocks)
    (early : Earlier Goldilocks)
    (targets : Fin 38 → Goldilocks) (later : Later Goldilocks)
    (selected : Fin 38 → LeafIndex) (tapes : TapeTable) :
    Fin 38 → Rp05FullRawInput bound :=
  fun i => Sum.inl (rp05SourceLeafInput statement salt
    (q38SelectedPublicData selected
      (q38PublicSuffix opening.points
        (computed_opening_selected_rank opening) gamma reply heads early
        targets later)
      (selected i)) (selected i) (tapes (selected i)))

private def currentP10PhysicalBatchInputs
    (bound : Nat) (statement : Statement) (salt : SaltBytes)
    (heads : Heads Goldilocks) (tails : Tails Goldilocks)
    (decsMask : Decs Goldilocks) (selected : Fin 38 → LeafIndex)
    (tapes : TapeTable) : Fin 38 → Rp05FullRawInput bound :=
  fun i => Sum.inl (rp05SourceLeafInput statement salt
    (q38PhysicalSuffix heads tails decsMask (selected i))
    (selected i) (tapes (selected i)))

private def currentP10SelectedBatchOracle
    (bound : Nat) (inputs : Fin 38 → Rp05FullRawInput bound)
    (labels : Fin 38 → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    Rp05FullRawInput bound → DigestRegister :=
  updateRp05Batch 38 inputs labels oldOracle

/-- A named atom for the public P10 oracle at a supplied chronological view.
The alias keeps the large selector/application expression out of the local
composition equality; callers that need the implementation use the explicit
readback theorem below. -/
private def currentP10PublicOracle
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (view : PartialView Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    Rp05FullRawInput bound → DigestRegister :=
  currentPublicOpenedOracle bound largeEnough dsl statement parameters gamma
    reply transcript digest pending salt tapes labels view oldOracle

/-- Package the concrete selector read and the independently derived
chronological/combination coordinates once. The private composition theorem
opens this package before applying its component identities, avoiding a
large dependent unification over the concrete tape-table carrier. -/
private structure CurrentP10SelectedBatchContext
    (bound : Nat) where
  largeEnough : 39162 ≤ bound
  dsl : RelationDsl
  statement : Statement
  parameters : Parameters dsl statement
  values : WitnessPackingValues Goldilocks
  base : RemainingCoins Goldilocks
  q : Q
  opening : ComputedOpening
  selected : IndexedTargets opening.points
  gamma : Gamma Goldilocks
  reply : D
  transcript : Q
  digest : DigestRegister
  pending : Bool
  salt : SaltBytes

private def currentP10ContextView
    {bound : Nat}
    (context : CurrentP10SelectedBatchContext bound) :
    PartialView Goldilocks :=
  (sourceWitnessOpenings context.values context.opening.points context.base.1,
   sourcePcsFullView context.opening.points
     (pcsBase context.opening.points context.q context.reply) context.base.2.1,
   earlier context.opening.points context.base.2.2,
   some (fullSubset (currentHeads context.values context.base context.q)
     context.base.2.2 (indexedPoints context.selected.val)))

private def currentP10ContextPublicOracle
    {bound : Nat}
    (context : CurrentP10SelectedBatchContext bound)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    Rp05FullRawInput bound → DigestRegister :=
  currentP10PublicOracle bound context.largeEnough context.dsl
    context.statement context.parameters context.gamma context.reply
    context.transcript context.digest context.pending context.salt tapes labels
    (currentP10ContextView context) oldOracle

private def currentP10ContextSelectedBatchOracle
    {bound : Nat}
    (context : CurrentP10SelectedBatchContext bound)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    Rp05FullRawInput bound → DigestRegister :=
  currentP10SelectedBatchOracle bound
    (currentP10SelectedBatchInputs bound context.statement context.salt
      context.opening context.gamma context.reply
      (lvcsPublicCombinationHeads context.opening.points
        (currentHeads context.values context.base context.q))
      (earlier context.opening.points context.base.2.2)
      (indexedPoints context.selected.val)
      (fullSubset (currentHeads context.values context.base context.q)
        context.base.2.2 (indexedPoints context.selected.val))
      context.selected.val tapes)
    (fun i => labels (context.selected.val i)) oldOracle

/-- Explicit readback from the named context atom to the actual public P10
oracle at its physical chronological view. Kept generic so the concrete
tape-table carrier is not unfolded while composing the endpoint. -/
private theorem currentP10ContextPublicOracle_readback
    {bound : Nat}
    (context : CurrentP10SelectedBatchContext bound)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    currentP10ContextPublicOracle context tapes labels oldOracle =
      currentPublicOpenedOracle bound context.largeEnough context.dsl
        context.statement context.parameters context.gamma context.reply
        context.transcript context.digest context.pending context.salt
        tapes labels
        (sourceWitnessOpenings context.values context.opening.points
           context.base.1,
         sourcePcsFullView context.opening.points
           (pcsBase context.opening.points context.q context.reply)
           context.base.2.1,
         earlier context.opening.points context.base.2.2,
         some (fullSubset
           (currentHeads context.values context.base context.q)
           context.base.2.2 (indexedPoints context.selected.val)))
        oldOracle := rfl

/-- Explicit readback of the named batch atom. This is used only where the
concrete accepted-oracle theorem exposes the update operation. -/
private theorem currentP10ContextSelectedBatchOracle_readback
    {bound : Nat}
    (context : CurrentP10SelectedBatchContext bound)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    currentP10ContextSelectedBatchOracle context tapes labels oldOracle =
      updateRp05Batch 38
        (currentP10SelectedBatchInputs bound context.statement
          context.salt context.opening context.gamma context.reply
          (lvcsPublicCombinationHeads context.opening.points
            (currentHeads context.values context.base context.q))
          (earlier context.opening.points context.base.2.2)
          (indexedPoints context.selected.val)
          (fullSubset (currentHeads context.values context.base context.q)
            context.base.2.2 (indexedPoints context.selected.val))
          context.selected.val tapes)
        (fun i => labels (context.selected.val i)) oldOracle := rfl

private theorem current_p10_selected_batch_eq_physical
    (bound : Nat) (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (heads : Heads Goldilocks)
    (tails : Tails Goldilocks) (decsMask : Decs Goldilocks)
    (selected : IndexedTargets opening.points)
    (statement : Statement) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister) :
    updateRp05Batch 38
      (currentP10SelectedBatchInputs bound statement salt opening gamma
        (V8SmzaMathPrivacy.response gamma heads tails decsMask)
        (lvcsPublicCombinationHeads opening.points heads)
        (earlier opening.points tails) (indexedPoints selected.val)
        (fullSubset heads tails (indexedPoints selected.val)) selected.val tapes)
      (fun i => labels (selected.val i)) oldOracle =
    updateRp05Batch 38
      (currentP10PhysicalBatchInputs bound statement salt heads tails decsMask
        selected.val tapes)
      (fun i => labels (selected.val i)) oldOracle := by
  rw [current_indexed_points_eq_evaluationPoint selected.val]
  exact (q38_selected_physical_overlay_eq_public
    (Other := Rp05OtherRawInput bound) opening.points
    (computed_opening_selected_rank opening) gamma heads tails decsMask
    selected.val selected.property.1 statement salt tapes
    (fun i => labels (selected.val i)) oldOracle).symm

/-- Once the measured selector has returned a successful target set, the
recorded-result adapter is definitionally the 38-write batch formed from the
view's own chronological coordinates. -/
private theorem current_public_from_result_eq_selected_batch
    (bound : Nat) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (gamma : Gamma Goldilocks) (reply : D)
    (transcript : Q) (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister) (view : PartialView Goldilocks)
    (result : SelectionResult opening.points)
    (selected : IndexedTargets opening.points) (later : Later Goldilocks)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (result_targets : result.targets = some selected)
    (view_later : view.2.2.2 = some later) :
    currentPublicOpenedOracleFromResult bound dsl statement parameters
        opening gamma reply transcript salt tapes labels view result oldOracle =
      updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (combinationHeads dsl statement parameters opening.points transcript
            view.1 view.2.1)
          view.2.2.1
          (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
            (selected.val i))
          later selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle := by
  have selectedIndices_eq : selectedIndices result = selected.val := by
    simp [selectedIndices, result_targets]
  simp only [currentPublicOpenedOracleFromResult, result_targets, view_later,
    selectedIndices_eq]
  rfl

private theorem current_public_opened_oracle_eq_current_batch
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (opening : ComputedOpening) (selected : IndexedTargets opening.points)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opened : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by omega) digest pending)) = some opening)
    (chosen : (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points (pcsBase opening.points q reply)
            base.2.1))
      (earlier opening.points base.2.2) opening.pendingFailure)).targets =
          some selected) :
    currentP10PublicOracle bound largeEnough dsl statement parameters
      gamma reply transcript digest pending salt tapes labels
      (sourceWitnessOpenings values opening.points base.1,
       sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1,
       earlier opening.points base.2.2,
       some (fullSubset (currentHeads values base q) base.2.2
         (indexedPoints selected.val))) oldOracle =
    currentP10SelectedBatchOracle bound
      (currentP10SelectedBatchInputs bound statement salt opening gamma reply
        (combinationHeads dsl statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points (pcsBase opening.points q reply)
            base.2.1))
        (earlier opening.points base.2.2)
        (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
          (selected.val i))
        (fullSubset (currentHeads values base q) base.2.2
          (indexedPoints selected.val)) selected.val tapes)
      (fun i => labels (selected.val i)) oldOracle := by
  dsimp only [currentP10PublicOracle, currentP10SelectedBatchOracle]
  let view : PartialView Goldilocks :=
    (sourceWitnessOpenings values opening.points base.1,
     sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1,
     earlier opening.points base.2.2,
     some (fullSubset (currentHeads values base q) base.2.2
       (indexedPoints selected.val)))
  let result := NonleafProgram.interpret
    (fun input => oldOracle (Sum.inr input))
    (currentSelectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript
        (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points (pcsBase opening.points q reply)
          base.2.1))
      (earlier opening.points base.2.2) opening.pendingFailure)
  have result_targets : result.targets = some selected := chosen
  let later : Later Goldilocks :=
    fullSubset (currentHeads values base q) base.2.2 (indexedPoints selected.val)
  have view_later : view.2.2.2 = some later := rfl
  have recordedResult := current_public_opened_oracle_uses_recorded_result
    bound largeEnough dsl statement parameters gamma reply transcript digest
    pending salt tapes labels view oldOracle opening opened
  have resultBatch := current_public_from_result_eq_selected_batch
    bound dsl statement parameters opening gamma reply transcript salt tapes
    labels view result selected later oldOracle result_targets view_later
  calc
    currentPublicOpenedOracle bound largeEnough dsl statement parameters
        gamma reply transcript digest pending salt tapes labels
        (sourceWitnessOpenings values opening.points base.1,
         sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1,
         earlier opening.points base.2.2,
         some (fullSubset (currentHeads values base q) base.2.2
           (indexedPoints selected.val))) oldOracle =
      currentPublicOpenedOracle bound largeEnough dsl statement parameters
        gamma reply transcript digest pending salt tapes labels view oldOracle := rfl
    _ = currentPublicOpenedOracleFromResult bound dsl statement parameters
        opening gamma reply transcript salt tapes labels view result oldOracle := by
      simpa only [result] using recordedResult
    _ = updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (combinationHeads dsl statement parameters opening.points transcript
            (sourceWitnessOpenings values opening.points base.1)
            (sourcePcsFullView opening.points (pcsBase opening.points q reply)
              base.2.1))
          (earlier opening.points base.2.2)
          (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
            (selected.val i))
          later selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle := resultBatch

private theorem current_p10_selected_batch_parameters_eq
    (bound : Nat) (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (opening : ComputedOpening) (selected : IndexedTargets opening.points)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (salt : SaltBytes) (tapes : TapeTable)
    (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (comboExact :
      combinationHeads dsl statement parameters opening.points transcript
        (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points (pcsBase opening.points q reply)
          base.2.1) =
        lvcsPublicCombinationHeads opening.points (currentHeads values base q)) :
    currentP10SelectedBatchOracle bound
      (currentP10SelectedBatchInputs bound statement salt opening gamma reply
        (combinationHeads dsl statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points (pcsBase opening.points q reply)
            base.2.1))
        (earlier opening.points base.2.2)
        (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
          (selected.val i))
        (fullSubset (currentHeads values base q) base.2.2
          (indexedPoints selected.val)) selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle =
    currentP10SelectedBatchOracle bound
      (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
        (earlier opening.points base.2.2) (indexedPoints selected.val)
        (fullSubset (currentHeads values base q) base.2.2
          (indexedPoints selected.val)) selected.val tapes)
      (fun i => labels (selected.val i)) oldOracle := by
  let later : Later Goldilocks :=
    fullSubset (currentHeads values base q) base.2.2 (indexedPoints selected.val)
  have headsBatch := congrArg
    (fun heads => updateRp05Batch 38
      (currentP10SelectedBatchInputs bound statement salt opening gamma reply
        heads (earlier opening.points base.2.2)
        (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
          (selected.val i)) later selected.val tapes)
      (fun i => labels (selected.val i)) oldOracle) comboExact
  have pointsEq :
      (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
        (selected.val i)) = indexedPoints selected.val :=
    (current_indexed_points_eq_evaluationPoint selected.val).symm
  have pointsBatch := congrArg
    (fun targets => updateRp05Batch 38
      (currentP10SelectedBatchInputs bound statement salt opening gamma reply
        (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
        (earlier opening.points base.2.2) targets later selected.val tapes)
      (fun i => labels (selected.val i)) oldOracle) pointsEq
  calc
    updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (combinationHeads dsl statement parameters opening.points transcript
            (sourceWitnessOpenings values opening.points base.1)
            (sourcePcsFullView opening.points (pcsBase opening.points q reply)
              base.2.1))
          (earlier opening.points base.2.2)
          (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
            (selected.val i))
          (fullSubset (currentHeads values base q) base.2.2
            (indexedPoints selected.val)) selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle =
      updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
          (earlier opening.points base.2.2)
          (fun i => HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint
            (selected.val i))
          later selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle := by
          simpa only [later] using headsBatch
    _ = updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
          (earlier opening.points base.2.2) (indexedPoints selected.val)
          later selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle := pointsBatch

private def current_accepted_p10_context
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (statement : Statement)
    (dsl : RelationDsl) (parameters : Parameters dsl statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (opening : ComputedOpening)
    (selected : IndexedTargets opening.points) :
    CurrentP10SelectedBatchContext bound := by
  let reply := V8SmzaMathPrivacy.response gamma
    (currentHeads values base q) base.2.2 m
  let transcript := Q38Rp05ChronologicalAlgebra.response
    dsl statement parameters (sourceWitnessPolynomials values base.1) q
  exact ⟨largeEnough, dsl, statement, parameters, values, base, q, opening,
    selected, gamma, reply, transcript, digest, pending, salt⟩

private theorem current_accepted_p10_combo_exact
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (reply : D)
    (opening : ComputedOpening)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    combinationHeads (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters opening.points
      (Q38Rp05ChronologicalAlgebra.response
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters (sourceWitnessPolynomials values base.1) q)
      (sourceWitnessOpenings values opening.points base.1)
      (sourcePcsFullView opening.points (pcsBase opening.points q reply)
        base.2.1) =
      lvcsPublicCombinationHeads opening.points (currentHeads values base q) := by
  exact rp05_accepted_combination_heads_are_physical
    components nonlinearRoot nodeDegree certificates statement parameters
    opening.points (computed_opening_interpolation_admissible opening)
    values base.1 q base.2.1 accepted

private theorem current_accepted_p10_chosen_physical
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    (digest : DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opening : ComputedOpening)
    (selected : IndexedTargets opening.points)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values))
    (chosen : (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
        (earlier opening.points base.2.2) opening.pendingFailure)).targets =
          some selected) :
    let transcript := Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters (sourceWitnessPolynomials values base.1) q
    (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads (normalizedDsl components nonlinearRoot nodeDegree)
          statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points
            (pcsBase opening.points q reply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure)).targets =
      some selected := by
  dsimp only
  let transcript := Q38Rp05ChronologicalAlgebra.response
    (normalizedDsl components nonlinearRoot nodeDegree)
    statement parameters (sourceWitnessPolynomials values base.1) q
  have comboExact := current_accepted_p10_combo_exact components nonlinearRoot
    nodeDegree certificates statement parameters values base q reply opening
    accepted
  have selectorProgramEq :
      currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads (normalizedDsl components nonlinearRoot nodeDegree)
          statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points
            (pcsBase opening.points q reply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure =
      currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (lvcsPublicCombinationHeads opening.points
          (currentHeads values base q))
        (earlier opening.points base.2.2) opening.pendingFailure := by
    exact congrArg
      (fun heads => currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest heads
        (earlier opening.points base.2.2) opening.pendingFailure)
      comboExact
  have selectorTargetsEq := congrArg
    (fun program =>
      (NonleafProgram.interpret
        (fun input => oldOracle (Sum.inr input)) program).targets)
    selectorProgramEq
  exact selectorTargetsEq.trans chosen

section CurrentP10BatchCarrierBoundary

attribute [local irreducible]
  currentP10PublicOracle currentP10SelectedBatchOracle

/-- Once the measured selector, physical view, and accepted combination-head
equation have been recorded, the public P10 oracle is the selected q38 batch.
The bridge is checked generically over one context while keeping these two
named oracle endpoints opaque at the composition boundary. -/
private theorem current_public_opened_oracle_eq_selected_batch
    {bound : Nat}
    (context : CurrentP10SelectedBatchContext bound)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opened : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by
        have boundLargeEnough := context.largeEnough
        omega) context.digest
        context.pending)) =
        some context.opening)
    (chosen : (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound context.largeEnough context.opening.points
        (computed_opening_points_distinct context.opening) context.digest
        (combinationHeads context.dsl context.statement context.parameters
          context.opening.points context.transcript
          (sourceWitnessOpenings context.values context.opening.points
            context.base.1)
          (sourcePcsFullView context.opening.points
            (pcsBase context.opening.points context.q context.reply)
            context.base.2.1))
        (earlier context.opening.points context.base.2.2)
        context.opening.pendingFailure)).targets = some context.selected)
    (comboExact : combinationHeads context.dsl context.statement
      context.parameters context.opening.points context.transcript
      (sourceWitnessOpenings context.values context.opening.points
        context.base.1)
      (sourcePcsFullView context.opening.points
        (pcsBase context.opening.points context.q context.reply)
        context.base.2.1) =
      lvcsPublicCombinationHeads context.opening.points
        (currentHeads context.values context.base context.q)) :
    currentP10ContextPublicOracle context tapes labels oldOracle =
      currentP10ContextSelectedBatchOracle context tapes labels oldOracle := by
  cases context with
  | mk largeEnough dsl statement parameters values base q opening selected
      gamma reply transcript digest pending salt =>
    dsimp only [currentP10ContextPublicOracle, currentP10ContextView,
      currentP10ContextSelectedBatchOracle]
    exact (current_public_opened_oracle_eq_current_batch
        bound largeEnough dsl statement parameters values base q opening selected
        gamma reply transcript digest pending salt tapes labels oldOracle opened
        chosen).trans
      (current_p10_selected_batch_parameters_eq
        bound dsl statement parameters values base q opening selected gamma
        reply transcript salt tapes labels oldOracle comboExact)

private theorem current_accepted_p10_oracle_eq_selected_batch
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opening : ComputedOpening)
    (selected : IndexedTargets opening.points)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values))
    (opened : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by omega) digest pending)) = some opening)
    (chosen : (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
        (earlier opening.points base.2.2) opening.pendingFailure)).targets =
          some selected) :
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters (sourceWitnessPolynomials values base.1) q
    currentPublicOpenedOracle bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters gamma reply transcript digest pending salt tapes
        labels
        (sourceWitnessOpenings values opening.points base.1,
         sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1,
         earlier opening.points base.2.2,
         some (fullSubset (currentHeads values base q) base.2.2
           (indexedPoints selected.val))) oldOracle =
      updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
          (earlier opening.points base.2.2) (indexedPoints selected.val)
          (fullSubset (currentHeads values base q) base.2.2
            (indexedPoints selected.val)) selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle := by
  dsimp only
  let reply := V8SmzaMathPrivacy.response gamma
    (currentHeads values base q) base.2.2 m
  let transcript := Q38Rp05ChronologicalAlgebra.response
    (normalizedDsl components nonlinearRoot nodeDegree)
    statement parameters (sourceWitnessPolynomials values base.1) q
  let bridge := current_accepted_p10_context bound largeEnough statement
    (normalizedDsl components nonlinearRoot nodeDegree) parameters values base
    q m gamma digest pending salt opening selected
  have comboExact := current_accepted_p10_combo_exact components nonlinearRoot
    nodeDegree certificates statement parameters values base q reply opening
    accepted
  have chosenPhysical := current_accepted_p10_chosen_physical
    components nonlinearRoot nodeDegree certificates bound largeEnough statement
    parameters values base q reply digest oldOracle opening selected
    accepted chosen
  calc
    currentPublicOpenedOracle bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters gamma reply transcript digest pending salt tapes
        labels
        (sourceWitnessOpenings values opening.points base.1,
         sourcePcsFullView opening.points (pcsBase opening.points q reply)
           base.2.1,
         earlier opening.points base.2.2,
         some (fullSubset (currentHeads values base q) base.2.2
           (indexedPoints selected.val))) oldOracle =
    currentP10ContextPublicOracle bridge tapes labels oldOracle :=
        (currentP10ContextPublicOracle_readback bridge tapes labels oldOracle).symm
    _ = currentP10ContextSelectedBatchOracle bridge tapes labels oldOracle :=
      current_public_opened_oracle_eq_selected_batch bridge tapes labels
        oldOracle opened chosenPhysical comboExact
    _ = updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
          (earlier opening.points base.2.2) (indexedPoints selected.val)
          (fullSubset (currentHeads values base q) base.2.2
            (indexedPoints selected.val)) selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle :=
      currentP10ContextSelectedBatchOracle_readback bridge tapes labels oldOracle

end CurrentP10BatchCarrierBoundary

/-- On the accepted successful branch, the P10 public oracle is exactly the
P8 opened-only oracle on the same old total oracle. No fresh sampler or
second selector read is introduced by this pointwise identity. -/
theorem current_accepted_p10_oracle_eq_p8_opened_oracle
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opening : ComputedOpening)
    (selected : IndexedTargets opening.points)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values))
    (opened : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by omega) digest pending)) = some opening)
    (chosen : (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
        (earlier opening.points base.2.2) opening.pendingFailure)).targets =
          some selected) :
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters (sourceWitnessPolynomials values base.1) q
    let view := partialChronologicalView values opening.points
      (fun _ => pcsBase opening.points q reply)
      (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
      (currentChooseTargets bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters opening transcript digest
        (fun input => oldOracle (Sum.inr input))) base
    currentPublicOpenedOracle bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters gamma reply transcript digest pending salt tapes
        labels view oldOracle =
      overlay (Other := Rp05OtherRawInput bound)
        (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input))
        labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (q38Unopened selected.val)ᶜ tapes := by
  dsimp only
  let reply := V8SmzaMathPrivacy.response gamma
    (currentHeads values base q) base.2.2 m
  let transcript := Q38Rp05ChronologicalAlgebra.response
    (normalizedDsl components nonlinearRoot nodeDegree)
    statement parameters (sourceWitnessPolynomials values base.1) q
  let view := partialChronologicalView values opening.points
    (fun _ => pcsBase opening.points q reply)
    (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
    (currentChooseTargets bound largeEnough
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters opening transcript digest
      (fun input => oldOracle (Sum.inr input))) base
  let physicalView : PartialView Goldilocks :=
    (sourceWitnessOpenings values opening.points base.1,
     sourcePcsFullView opening.points (pcsBase opening.points q reply) base.2.1,
     earlier opening.points base.2.2,
     some (fullSubset (currentHeads values base q) base.2.2
       (indexedPoints selected.val)))
  have view_eq : view = physicalView := by
    exact current_successful_partial_view_is_physical components nonlinearRoot
      nodeDegree certificates bound largeEnough statement parameters opening
      values base q reply digest (fun input => oldOracle (Sum.inr input))
      selected accepted chosen
  have publicBatch := current_accepted_p10_oracle_eq_selected_batch
    components nonlinearRoot nodeDegree certificates bound largeEnough
    statement parameters values base q m gamma digest pending salt tapes labels
    oldOracle opening selected accepted opened chosen
  have viewTransport := congrArg
      (fun candidate : PartialView Goldilocks =>
        currentPublicOpenedOracle bound largeEnough
          (normalizedDsl components nonlinearRoot nodeDegree)
          statement parameters gamma reply transcript digest pending salt tapes
          labels candidate oldOracle)
      view_eq
  calc
    currentPublicOpenedOracle bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters gamma reply transcript digest pending salt tapes
        labels view oldOracle =
      currentPublicOpenedOracle bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters gamma reply transcript digest pending salt tapes
        labels physicalView oldOracle := viewTransport
    _ = updateRp05Batch 38
        (currentP10SelectedBatchInputs bound statement salt opening gamma reply
          (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
          (earlier opening.points base.2.2) (indexedPoints selected.val)
          (fullSubset (currentHeads values base q) base.2.2
            (indexedPoints selected.val)) selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle := by
      simpa only [physicalView] using publicBatch
    _ = updateRp05Batch 38
        (currentP10PhysicalBatchInputs bound statement salt
          (currentHeads values base q) base.2.2 m selected.val tapes)
        (fun i => labels (selected.val i)) oldOracle := by
      exact current_p10_selected_batch_eq_physical bound opening gamma
        (currentHeads values base q) base.2.2 m selected statement salt tapes
        labels oldOracle
    _ = overlay (Other := Rp05OtherRawInput bound)
        (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input)) labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (q38Unopened selected.val)ᶜ tapes :=
      (current_opened_overlay_eq_batch bound statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        selected.val selected.property.1 labels tapes oldOracle).symm

/-- The P8/P10 oracle equality in the form needed by a measured game: the
selector result is supplied as a recorded outcome, and this construction
does not query the oracle again. The `recorded` premise identifies that
outcome with the current selector on the same fixed pre-opening oracle. -/
theorem current_accepted_recorded_p10_oracle_eq_p8_opened_oracle
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (m : D)
    (gamma : Gamma Goldilocks)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tapes : TapeTable) (labels : LeafIndex → DigestRegister)
    (oldOracle : Rp05FullRawInput bound → DigestRegister)
    (opening : ComputedOpening)
    (selected : IndexedTargets opening.points)
    (result : SelectionResult opening.points)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values))
    (opened : certifyOpening (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (rp05ChooseOpening bound (by omega) digest pending)) = some opening)
    (chosen : (NonleafProgram.interpret
      (fun input => oldOracle (Sum.inr input))
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (lvcsPublicCombinationHeads opening.points (currentHeads values base q))
        (earlier opening.points base.2.2) opening.pendingFailure)).targets =
          some selected)
    (recorded :
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      let transcript := Q38Rp05ChronologicalAlgebra.response
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters (sourceWitnessPolynomials values base.1) q
      let view := partialChronologicalView values opening.points
        (fun _ => pcsBase opening.points q reply)
        (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
        (currentChooseTargets bound largeEnough
          (normalizedDsl components nonlinearRoot nodeDegree)
          statement parameters opening transcript digest
          (fun input => oldOracle (Sum.inr input))) base
      result = NonleafProgram.interpret
        (fun input => oldOracle (Sum.inr input))
        (currentSelectIndices bound largeEnough opening.points
          (computed_opening_points_distinct opening) digest
          (combinationHeads
            (normalizedDsl components nonlinearRoot nodeDegree)
            statement parameters opening.points transcript view.1 view.2.1)
          view.2.2.1 opening.pendingFailure)) :
    let reply := V8SmzaMathPrivacy.response gamma
      (currentHeads values base q) base.2.2 m
    let transcript := Q38Rp05ChronologicalAlgebra.response
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters (sourceWitnessPolynomials values base.1) q
    let view := partialChronologicalView values opening.points
      (fun _ => pcsBase opening.points q reply)
      (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
      (currentChooseTargets bound largeEnough
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters opening transcript digest
        (fun input => oldOracle (Sum.inr input))) base
    currentPublicOpenedOracleFromResult bound
        (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters opening gamma reply transcript salt tapes labels
        view result oldOracle =
      overlay (Other := Rp05OtherRawInput bound)
        (fun input => oldOracle (Sum.inl input))
        (fun input => oldOracle (Sum.inr input))
        labels statement salt
        (q38PhysicalSuffix (currentHeads values base q) base.2.2 m)
        (q38Unopened selected.val)ᶜ tapes := by
  let reply := V8SmzaMathPrivacy.response gamma
    (currentHeads values base q) base.2.2 m
  let transcript := Q38Rp05ChronologicalAlgebra.response
    (normalizedDsl components nonlinearRoot nodeDegree)
    statement parameters (sourceWitnessPolynomials values base.1) q
  let view := partialChronologicalView values opening.points
    (fun _ => pcsBase opening.points q reply)
    (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
    (currentChooseTargets bound largeEnough
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement parameters opening transcript digest
      (fun input => oldOracle (Sum.inr input))) base
  have same := current_public_opened_oracle_uses_recorded_result
    bound largeEnough (normalizedDsl components nonlinearRoot nodeDegree)
    statement parameters gamma reply transcript digest pending salt tapes
    labels view oldOracle opening opened
  rw [recorded]
  exact same.symm.trans
    (current_accepted_p10_oracle_eq_p8_opened_oracle
      components nonlinearRoot nodeDegree certificates bound largeEnough
      statement parameters values base q m gamma digest pending salt tapes
      labels oldOracle opening selected accepted opened chosen)

/-- The same current selector, followed by the existing q38 serializer on
the supplied chronological view. -/
def currentSelectedProgramWithView
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (view : PartialView Goldilocks) :
    NonleafProgram (Rp05OtherRawInput bound) (Except String (List Byte)) :=
  NonleafProgram.bind
    (currentSelectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript
        view.1 view.2.1) view.2.2.1 opening.pendingFailure)
    fun result => .done
      (selectedBytes dsl statement parameters opening gamma reply transcript
        digest salt tree tapes view result)

theorem current_selected_program_interpret
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (view : PartialView Goldilocks)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (currentSelectedProgramWithView bound largeEnough dsl statement
        parameters opening gamma reply transcript digest salt tree tapes view) =
      let job := NonleafProgram.interpret oracle
        (currentSelectIndices bound largeEnough opening.points
          (computed_opening_points_distinct opening) digest
          (combinationHeads dsl statement parameters opening.points transcript
            view.1 view.2.1) view.2.2.1 opening.pendingFailure)
      selectedBytes dsl statement parameters opening gamma reply transcript
        digest salt tree tapes view job := by
  simp only [currentSelectedProgramWithView, NonleafProgram.interpret_bind,
    NonleafProgram.interpret]

/-- The P10 serializer consumes the selector outcome recorded by the current
physical game. The public chronological view is constructed from that same
outcome, so neither the successful bytes nor the index-exhaustion error
needs a second oracle read. -/
theorem current_selected_bytes_from_recorded_result
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q) (reply : D)
    (gamma : Gamma Goldilocks) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (result : SelectionResult opening.points)
    (recorded : result = NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points
            (pcsBase opening.points q reply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure)) :
    selectedBytes dsl statement parameters opening gamma reply transcript
        digest salt tree tapes
        (selectedPhysicalView values base q reply result) result =
      let view := partialChronologicalView values opening.points
        (fun _ => pcsBase opening.points q reply)
        (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
        (currentChooseTargets bound largeEnough dsl statement parameters
          opening transcript digest oracle) base
      NonleafProgram.interpret oracle
        (currentSelectedProgramWithView bound largeEnough dsl statement
          parameters opening gamma reply transcript digest salt tree tapes
          view) := by
  rw [recorded]
  rw [current_selected_program_interpret]
  rw [current_partial_view_eq_recorded_result bound largeEnough dsl statement
    parameters opening values base q reply transcript digest oracle]
  rfl

/-- At one fixed corrected oracle, the actual selected-byte branch equals
the P10 source kernel on the chronological physical view. -/
theorem current_honest_selected_eq_source_kernel
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (currentHonestSelectedProgram bound largeEnough dsl statement
        parameters opening values base q gamma reply transcript digest salt
        tree tapes) =
    let view := partialChronologicalView values opening.points
      (fun _ => pcsBase opening.points q reply)
      (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
      (currentChooseTargets bound largeEnough dsl statement parameters opening
        transcript digest oracle) base
    NonleafProgram.interpret oracle
      (currentSelectedProgramWithView bound largeEnough dsl statement
        parameters opening gamma reply transcript digest salt tree tapes view) := by
  let result := NonleafProgram.interpret oracle
    (currentSelectIndices bound largeEnough opening.points
      (computed_opening_points_distinct opening) digest
      (combinationHeads dsl statement parameters opening.points transcript
        (sourceWitnessOpenings values opening.points base.1)
        (sourcePcsFullView opening.points
          (pcsBase opening.points q reply) base.2.1))
      (earlier opening.points base.2.2) opening.pendingFailure)
  have recorded : result = NonleafProgram.interpret oracle
      (currentSelectIndices bound largeEnough opening.points
        (computed_opening_points_distinct opening) digest
        (combinationHeads dsl statement parameters opening.points transcript
          (sourceWitnessOpenings values opening.points base.1)
          (sourcePcsFullView opening.points
            (pcsBase opening.points q reply) base.2.1))
        (earlier opening.points base.2.2) opening.pendingFailure) := rfl
  simpa only [currentHonestSelectedProgram, NonleafProgram.interpret_bind,
    NonleafProgram.interpret, currentSelectedPhysicalView, selectedPhysicalView]
    using (current_selected_bytes_from_recorded_result bound largeEnough dsl
      statement parameters opening values base q reply gamma transcript digest
      salt tree tapes oracle result recorded)

/-- The source factorization also retains the actual 16-nonce exhaustion
branch before any selected-index read. -/
theorem current_post_final_eq_source_kernel
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (values : WitnessPackingValues Goldilocks)
    (base : RemainingCoins Goldilocks) (q : Q)
    (gamma : Gamma Goldilocks) (reply : D) (transcript : Q)
    (digest : DigestRegister) (pending : Bool) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister) :
    NonleafProgram.interpret oracle
      (currentHonestPostFinalProgram bound largeEnough dsl statement
        parameters values base q gamma reply transcript digest pending salt
        tree tapes) =
    match certifyOpening (NonleafProgram.interpret oracle
        (rp05ChooseOpening bound (by omega) digest pending)) with
    | none => .error "smallwood opening nonce trial limit exhausted"
    | some opening =>
        let view := partialChronologicalView values opening.points
          (fun _ => pcsBase opening.points q reply)
          (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
          (currentChooseTargets bound largeEnough dsl statement parameters
            opening transcript digest oracle) base
        NonleafProgram.interpret oracle
          (currentSelectedProgramWithView bound largeEnough dsl statement
            parameters opening gamma reply transcript digest salt tree tapes
            view) := by
  simp only [currentHonestPostFinalProgram, NonleafProgram.interpret_bind]
  cases selected : certifyOpening (NonleafProgram.interpret oracle
      (rp05ChooseOpening bound (by omega) digest pending)) with
  | none => rfl
  | some opening =>
      exact current_honest_selected_eq_source_kernel bound largeEnough dsl
        statement parameters opening values base q gamma reply transcript
        digest salt tree tapes oracle

set_option maxRecDepth 100000
/-- P10's q38 coordinate transport with the current-profile selector and
serializer, for an arbitrary additive fixed-oracle observation. -/
theorem current_selected_program_is_public_state_kernel
    {Value : Type*} [AddCommMonoid Value]
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (gamma : Gamma Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (observe : D → Q → Except String (List Byte) → Value) :
    (∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m,
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      let publicTranscript := Q38Rp05ChronologicalAlgebra.response
        dsl statement parameters (sourceWitnessPolynomials values base.1) q
      let view := partialChronologicalView values opening.points
        (fun _ => pcsBase opening.points q reply)
        (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
        (currentChooseTargets bound largeEnough dsl statement parameters
          opening publicTranscript digest oracle) base
      observe reply publicTranscript
        (NonleafProgram.interpret oracle
          (currentSelectedProgramWithView bound largeEnough dsl statement
            parameters opening gamma reply publicTranscript digest salt tree
            tapes view))) =
    ∑ reply, ∑ publicTranscript, ∑ view : RemainingView Goldilocks,
      let projectedView := abortProjection
        (currentChooseTargets bound largeEnough dsl statement parameters
          opening publicTranscript digest oracle) view
      observe reply publicTranscript
        (NonleafProgram.interpret oracle
          (currentSelectedProgramWithView bound largeEnough dsl statement
            parameters opening gamma reply publicTranscript digest salt tree
            tapes projectedView)) := by
  have transported := request_public_opening_state_kernel_sum
    (PublicBranch := Unit) (Value := Value) dsl statement gamma values
    (fun _reply _branch => parameters)
    (fun _reply _branch _transcript => opening.points)
    (fun _reply _branch _transcript =>
      computed_opening_interpolation_admissible opening)
    (fun _reply _branch _transcript =>
      computed_opening_points_nonzero opening)
    (fun _reply _branch _transcript =>
      ⟨indexedPoints (fun index : Fin 38 =>
          ⟨index.val, index.isLt.trans (by decide)⟩),
        indexed_targets_admissible opening.points
          (computed_opening_points_distinct opening)
          (fun index : Fin 38 =>
            ⟨index.val, index.isLt.trans (by decide)⟩)
          (by intro left right same
              exact Fin.ext (congrArg (fun index : LeafIndex => index.val)
                same))⟩)
    (fun _reply _branch transcript =>
      currentChooseTargets bound largeEnough dsl statement parameters
        opening transcript digest oracle)
    (fun reply _branch transcript view =>
      observe reply transcript
        (NonleafProgram.interpret oracle
          (currentSelectedProgramWithView bound largeEnough dsl statement
            parameters opening gamma reply transcript digest salt tree tapes
            view)))
  simp only [Fintype.sum_unique] at transported
  have heads_eq (q : Q) :
      (fun witness pcs => currentP10PhysicalHeads values witness q pcs) =
        (fun witness pcs =>
          physicalHeads (sourceWitnessPolynomials values witness) q pcs) := by
    funext witness pcs
    exact currentP10PhysicalHeads_eq values witness q pcs
  simp_rw [heads_eq]
  exact transported

set_option maxRecDepth 10000
set_option maxRecDepth 100000
/-- P10 with the whole public view supplied to the continuation. In
particular the observation can run the next program on
`currentPublicOpenedOracle ... view oldOracle`, so the q38 coordinate
transport applies to the opened oracle writes as well as serialized bytes. -/
theorem current_selected_program_and_oracle_state_kernel
    {Value : Type*} [AddCommMonoid Value]
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (gamma : Gamma Goldilocks)
    (values : WitnessPackingValues Goldilocks)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (observe : D → Q → PartialView Goldilocks →
      Except String (List Byte) → Value) :
    (∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m,
      let reply := V8SmzaMathPrivacy.response gamma
        (currentHeads values base q) base.2.2 m
      let publicTranscript := Q38Rp05ChronologicalAlgebra.response
        dsl statement parameters (sourceWitnessPolynomials values base.1) q
      let view := partialChronologicalView values opening.points
        (fun _ => pcsBase opening.points q reply)
        (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
        (currentChooseTargets bound largeEnough dsl statement parameters
          opening publicTranscript digest oracle) base
      observe reply publicTranscript view
        (NonleafProgram.interpret oracle
          (currentSelectedProgramWithView bound largeEnough dsl statement
            parameters opening gamma reply publicTranscript digest salt tree
            tapes view))) =
    ∑ reply, ∑ publicTranscript, ∑ view : RemainingView Goldilocks,
      let projectedView := abortProjection
        (currentChooseTargets bound largeEnough dsl statement parameters
          opening publicTranscript digest oracle) view
      observe reply publicTranscript projectedView
        (NonleafProgram.interpret oracle
          (currentSelectedProgramWithView bound largeEnough dsl statement
            parameters opening gamma reply publicTranscript digest salt tree
            tapes projectedView)) := by
  have transported := request_public_opening_state_kernel_sum
    (PublicBranch := Unit) (Value := Value) dsl statement gamma values
    (fun _reply _branch => parameters)
    (fun _reply _branch _transcript => opening.points)
    (fun _reply _branch _transcript =>
      computed_opening_interpolation_admissible opening)
    (fun _reply _branch _transcript =>
      computed_opening_points_nonzero opening)
    (fun _reply _branch _transcript =>
      ⟨indexedPoints (fun index : Fin 38 =>
          ⟨index.val, index.isLt.trans (by decide)⟩),
        indexed_targets_admissible opening.points
          (computed_opening_points_distinct opening)
          (fun index : Fin 38 =>
            ⟨index.val, index.isLt.trans (by decide)⟩)
          (by intro left right same
              exact Fin.ext (congrArg (fun index : LeafIndex => index.val)
                same))⟩)
    (fun _reply _branch transcript =>
      currentChooseTargets bound largeEnough dsl statement parameters
        opening transcript digest oracle)
    (fun reply _branch transcript view =>
      observe reply transcript view
        (NonleafProgram.interpret oracle
          (currentSelectedProgramWithView bound largeEnough dsl statement
            parameters opening gamma reply transcript digest salt tree tapes
            view)))
  simp only [Fintype.sum_unique] at transported
  have heads_eq (q : Q) :
      (fun witness pcs => currentP10PhysicalHeads values witness q pcs) =
        (fun witness pcs =>
          physicalHeads (sourceWitnessPolynomials values witness) q pcs) := by
    funext witness pcs
    exact currentP10PhysicalHeads_eq values witness q pcs
  simp_rw [heads_eq]
  exact transported

set_option maxRecDepth 10000
/-- Exact two-witness current P10 algebra for any additive observation of
the public response/transcript/view and serialized bytes. In particular an
observer may run a downstream program on the public opened oracle. This is
not yet the Born-weighted physical-game privacy inequality. -/
theorem current_p10_two_witness_oracle_state
    {Value : Type*} [AddCommMonoid Value]
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (opening : ComputedOpening) (gamma : Gamma Goldilocks)
    (left right : WitnessPackingValues Goldilocks)
    (digest : DigestRegister) (salt : SaltBytes)
    (tree : List (List DigestRegister)) (tapes : TapeTable)
    (oracle : Rp05OtherRawInput bound → DigestRegister)
    (observe : D → Q → PartialView Goldilocks →
      Except String (List Byte) → Value) :
    let source := fun values : WitnessPackingValues Goldilocks =>
      ∑ base : RemainingCoins Goldilocks, ∑ q, ∑ m,
        let reply := V8SmzaMathPrivacy.response gamma
          (currentHeads values base q) base.2.2 m
        let publicTranscript := Q38Rp05ChronologicalAlgebra.response
          dsl statement parameters (sourceWitnessPolynomials values base.1) q
        let view := partialChronologicalView values opening.points
          (fun _ => pcsBase opening.points q reply)
          (fun witness pcs => currentP10PhysicalHeads values witness q pcs)
          (currentChooseTargets bound largeEnough dsl statement parameters
            opening publicTranscript digest oracle) base
        observe reply publicTranscript view
          (NonleafProgram.interpret oracle
            (currentSelectedProgramWithView bound largeEnough dsl statement
              parameters opening gamma reply publicTranscript digest salt tree
              tapes view))
    source left = source right := by
  exact (current_selected_program_and_oracle_state_kernel bound largeEnough
    dsl statement parameters opening gamma left digest salt tree tapes oracle
    observe).trans
    (current_selected_program_and_oracle_state_kernel bound largeEnough
      dsl statement parameters opening gamma right digest salt tree tapes oracle
      observe).symm

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentP10
