import SmzaRp04ScalarCheckTransport
import HegemonCrypto.SmallWoodDecsRestore

/-! Restoration and actual q38 column readback imply packed program acceptance.
Transcript binding and the named algebraic detection events remain explicit.
No decoder-success, program-success, or probability bound is assumed here. -/
namespace HegemonCrypto.SmallWood.SmzaRp04RestoredTranscriptChecks

open Polynomial SmzaQ38Recovery SmzaRp04ActualProgram SmzaRp04ScalarCheckTransport
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open SmzaRp04PublicContext V8Smz9EagerPrivacy V8Smz9EagerSimulator
open V8Smz9ZeroKnowledge
open scoped BigOperators
noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000
set_option backward.isDefEq.respectTransparency false

def denominator (point : Goldilocks) : Goldilocks :=
  (Interactive.packingVanishing (Finset.univ : Finset (Fin 64)) packingPoint).eval point

theorem admissible_denominator_nonzero (opening : Opening) (coordinate : Fin 6) :
    denominator (baseOpeningPoints opening.1 coordinate) ≠ 0 := by
  unfold denominator Interactive.packingVanishing
  simp only [eval_prod, eval_sub, eval_X, eval_C]
  apply Finset.prod_ne_zero_iff.mpr
  intro lane _
  apply sub_ne_zero.mpr
  intro equal
  apply baseOpeningPoints_outside_packing opening.1 coordinate
  apply Finset.mem_map.mpr
  exact ⟨lane, Finset.mem_univ _, equal.symm⟩

def nonlinearRestored (publicWords : List Nat) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (highPart : Fin 5 → Goldilocks[X])
    (row : Fin 5) : Goldilocks[X] :=
  DecsRestore.restorePolynomial Finset.univ (baseOpeningPoints opening.1) (highPart row)
    (fun coordinate =>
      (∑ check, matrix row check * nonlinearAt publicWords (witness coordinate) check) /
        denominator (baseOpeningPoints opening.1 coordinate) + masks.1 coordinate row)

def linearValues (publicWords : List Nat) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (row : Fin 5) : Option (Fin 6) → Goldilocks
  | none => 0
  | some index => (∑ check, matrix row check * linearAt publicWords (witness index)
      (baseOpeningPoints opening.1 index) check) + masks.2 index row

def linearRestored (publicWords : List Nat) (matrix : Matrix (batchingWidth publicWords))
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (highPart : Fin 5 → Goldilocks[X])
    (correction : Fin 5 → Goldilocks) (row : Fin 5) : Goldilocks[X] :=
  DecsRestore.restorePolynomial Finset.univ
      (LinearPiopExact.augmentedPoint (baseOpeningPoints opening.1)) (highPart row)
      (linearValues publicWords matrix opening witness masks row) +
    C (correction row) * LinearPiopExact.normalizedRootPolynomial (baseOpeningPoints opening.1)

def SameRestoredTranscript (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (nonlinearHigh linearHigh : Fin 5 → Goldilocks[X])
    (correction : Fin 5 → Goldilocks) : Prop :=
  (∀ row, response.nonlinear row = nonlinearRestored publicWords matrix opening witness masks
    nonlinearHigh row) ∧
  (∀ row, claimedLinear (recoveredCandidate publicWords rows) matrix response row =
    linearRestored publicWords matrix opening witness masks linearHigh correction row)

theorem restored_transcript_supplies_scalar_checks
    (publicWords : List Nat) (rows : RecoveredRows)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (nonlinearHigh linearHigh : Fin 5 → Goldilocks[X])
    (correction : Fin 5 → Goldilocks)
    (bound : SameRestoredTranscript publicWords rows matrix response opening witness masks
      nonlinearHigh linearHigh correction) :
    ScalarChecks publicWords rows matrix response opening witness masks := by
  have pointInjective := baseOpeningPoints_injective opening.1
  have nonzero : ∀ coordinate, baseOpeningPoints opening.1 coordinate ≠ 0 := by
    intro coordinate zero
    exact baseOpeningPoints_outside_packing opening.1 coordinate (zero ▸ zero_mem_packingDomain)
  have augmentedInjective := LinearPiopExact.augmentedPoint_injective pointInjective nonzero
  intro row coordinate
  constructor
  · rw [bound.1 row]
    unfold nonlinearRestored
    rw [DecsRestore.restore_polynomial_eval pointInjective.injOn (Finset.mem_univ coordinate)]
    change denominator _ * (_ / denominator _ + _ - _) = _
    rw [add_sub_cancel_right, mul_div_cancel₀ _ (admissible_denominator_nonzero opening coordinate)]
  · rw [bound.2 row]
    unfold linearRestored
    rw [eval_add, eval_mul, eval_C, LinearPiopExact.normalizedRootPolynomial_eval_opening,
      mul_zero, add_zero]
    have evaluates := DecsRestore.restore_polynomial_eval
      (highPart := linearHigh row)
      (evaluations := linearValues publicWords matrix opening witness masks row)
      augmentedInjective.injOn (Finset.mem_univ (some coordinate))
    change (DecsRestore.restorePolynomial _ _ _ _).eval
      (baseOpeningPoints opening.1 coordinate) = _ at evaluates
    simpa only [linearValues, add_sub_cancel_right] using
      congrArg (fun value : Goldilocks => value - masks.2 coordinate row) evaluates

theorem restored_columns_outside_algebraic_events_supply_actual_program
    (publicWords : List Nat) (rows : RecoveredRows)
    (canonicalPublic : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (nonlinearHigh linearHigh : Fin 5 → Goldilocks[X]) (correction : Fin 5 → Goldilocks)
    (bound : SameRestoredTranscript publicWords rows matrix response opening witness masks
      nonlinearHigh linearHigh correction)
    (columns : reconstructedColumnEvaluations (baseOpeningPoints opening.1) witness masks partials =
      (fun coordinate column => (SmzaQ38LvcsOpening.recoveredColumn rows column).eval
        (baseOpeningPoints opening.1 coordinate)))
    (roots : SmzaPiopGoodOutcome.DiscrepanciesDetected
      (recoveredCandidate publicWords rows) matrix response opening)
    (residuals : SmzaPiopGoodOutcome.ResidualsDetected (recoveredCandidate publicWords rows) matrix) :
    SmzaRp04Components.program.AcceptsPacked
      publicWords (packedFromRows rows) := by
  exact accepted_recovered_q38_piop_supplies_actual_program publicWords rows canonicalPublic
    matrix response opening
    (reconstructed_columns_and_actual_checks_imply_opening_acceptance publicWords rows
      matrix response opening witness masks partials columns
      (restored_transcript_supplies_scalar_checks publicWords rows matrix response opening
        witness masks nonlinearHigh linearHigh correction bound)) roots residuals

theorem accepted_restored_oracle_outside_algebraic_events_supply_actual_program
    (publicWords : List Nat) (rows : RecoveredRows)
    (canonicalPublic : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (matrix : Matrix (batchingWidth publicWords)) (response : ClaimedTranscript)
    (opening : Opening) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (nonlinearHigh linearHigh : Fin 5 → Goldilocks[X]) (correction : Fin 5 → Goldilocks)
    (bound : SameRestoredTranscript publicWords rows matrix response opening witness masks
      nonlinearHigh linearHigh correction)
    (oracle : SmzaQ38OracleExtraction.CommittedOracle)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (query : SmzaQ38McaSourceBinding.Query)
    (headBinding : SmzaQ38OpeningFieldReadback.ClaimedHeadsReconstructed
      (baseOpeningPoints opening.1) claimed witness masks partials)
    (rowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (SmzaQ38OracleExtraction.smz9EvaluationPoint index) =
        SmzaQ38OracleExtraction.committedColumnValue oracle row index)
    (checked : SmzaQ38LvcsOpening.OracleOpeningChecks oracle
      (baseOpeningPoints opening.1) claimed query)
    (lvcsDetected : SmzaQ38LvcsOpening.DiscrepanciesDetected rows
      (baseOpeningPoints opening.1) claimed query)
    (roots : SmzaPiopGoodOutcome.DiscrepanciesDetected
      (recoveredCandidate publicWords rows) matrix response opening)
    (residuals : SmzaPiopGoodOutcome.ResidualsDetected (recoveredCandidate publicWords rows) matrix) :
    SmzaRp04Components.program.AcceptsPacked
      publicWords (packedFromRows rows) := by
  exact restored_columns_outside_algebraic_events_supply_actual_program publicWords rows
    canonicalPublic matrix response opening witness masks partials nonlinearHigh linearHigh correction
    bound (SmzaQ38OpeningFieldReadback.accepted_heads_force_every_reconstructed_column
      oracle rows (baseOpeningPoints opening.1) claimed query witness masks partials headBinding
      rowAgreement checked lvcsDetected) roots residuals

end
end HegemonCrypto.SmallWood.SmzaRp04RestoredTranscriptChecks
