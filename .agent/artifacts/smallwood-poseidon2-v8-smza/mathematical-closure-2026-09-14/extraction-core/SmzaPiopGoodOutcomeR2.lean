import HegemonCrypto.SmallWoodV8Smz9PiopSoundness

/-! Deterministic PIOP good-outcome implication. The candidate precedes gamma;
the response precedes the six openings. Premises concern fixed residual vectors
and the ten actual discrepancy polynomials, never extraction success. This file
does not import the old q20 DECS count or assert a quantum event bound. -/

namespace HegemonCrypto.SmallWood.SmzaPiopGoodOutcome

open Polynomial
open scoped BigOperators
open V8Smz9PiopSoundness
open V8Smz9AdmissibleRootProbability
open HegemonCrypto.SmallWoodPowerBatching

noncomputable section
set_option maxHeartbeats 800000
set_option maxRecDepth 10000

/-- Each nonzero *pre-opening* discrepancy is detected by at least one of the
six openings. Only these ten polynomials occur, not all degree552 polynomials. -/
def DiscrepanciesDetected {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (opening : Opening) : Prop :=
  (∀ row, nonlinearDiscrepancy candidate matrix response row ≠ 0 →
    ∃ coordinate, (nonlinearDiscrepancy candidate matrix response row).eval
      (V8Smz9AdaptiveFiniteAccounting.baseOpeningPoints opening.1 coordinate) ≠ 0) ∧
  (∀ row, linearDiscrepancy candidate matrix response row ≠ 0 →
    ∃ coordinate, (linearDiscrepancy candidate matrix response row).eval
      (V8Smz9AdaptiveFiniteAccounting.baseOpeningPoints opening.1 coordinate) ≠ 0)

/-- Actual nonlinear residuals at the64 packing nodes and the actual linear
target residual are not annihilated by all5 rows. Arbitrary precommitted mask
sums remain included in the affine linear equation. No mask-zero assumption. -/
def ResidualsDetected {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) : Prop :=
  (∀ node : Fin 64,
    (∃ check, PiopExtraction.nonlinearResidual candidate.system node check ≠ 0) →
    ∃ row, uniformDotProduct (PiopExtraction.nonlinearResidual candidate.system node)
      (matrix row) ≠ 0) ∧
  ((∃ check, PiopExtraction.linearResidual candidate.system check ≠ 0) →
    ∃ row, uniformDotProduct (PiopExtraction.linearResidual candidate.system)
      (matrix row) ≠ -maskSum candidate row)

theorem accepted_openings_force_actual_discrepancies_zero {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width)
    (response : ClaimedTranscript) (opening : Opening)
    (accepted : OpeningAccepts candidate matrix response opening)
    (detected : DiscrepanciesDetected candidate matrix response opening) :
    (∀ row, nonlinearDiscrepancy candidate matrix response row = 0) ∧
      (∀ row, linearDiscrepancy candidate matrix response row = 0) := by
  constructor
  · intro row
    by_contra nonzero
    obtain ⟨coordinate, mismatch⟩ := detected.1 row nonzero
    exact mismatch (accepted row coordinate).1
  · intro row
    by_contra nonzero
    obtain ⟨coordinate, mismatch⟩ := detected.2 row nonzero
    exact mismatch (accepted row coordinate).2

theorem zero_discrepancies_force_affine_packing_checks {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width) (response : ClaimedTranscript)
    (nonlinearZero : ∀ row, nonlinearDiscrepancy candidate matrix response row = 0)
    (linearZero : ∀ row, linearDiscrepancy candidate matrix response row = 0) :
    PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix := by
  intro row
  constructor
  · intro node membership
    by_contra failure
    have nonzero : nonlinearDiscrepancy candidate matrix response row ≠ 0 :=
      PiopEvaluation.consistency_discrepancy_ne_zero_of_batch_failure
        candidate.system.nodes candidate.system.point
        (PiopExtraction.nonlinearBatch candidate.system (matrix row))
        (response.nonlinear row) (candidate.nonlinearMask row) node membership failure
    exact nonzero (nonlinearZero row)
  · by_contra failure
    exact (linear_discrepancy_ne_zero candidate matrix response row failure) (linearZero row)

theorem affine_checks_force_nonlinear_residual_dot_zero {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width)
    (affine : PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix)
    (row : Fin 5) (node : Fin 64) :
    uniformDotProduct (PiopExtraction.nonlinearResidual candidate.system node) (matrix row) = 0 := by
  have checked := (affine row).1 node (by simp [Candidate.system])
  simpa [uniformDotProduct, PiopExtraction.nonlinearResidual,
    PiopExtraction.nonlinearBatch, Interactive.batch, Polynomial.eval_finsetSum,
    Polynomial.eval_mul, mul_comm] using checked

theorem detected_residuals_and_affine_checks_force_full_system {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width)
    (affine : PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix)
    (detected : ResidualsDetected candidate matrix) :
    PiopExtraction.FullySatisfied candidate.system := by
  constructor
  · intro check node membership
    by_contra failure
    obtain ⟨row, mismatch⟩ := detected.1 node ⟨check, failure⟩
    exact mismatch (affine_checks_force_nonlinear_residual_dot_zero candidate matrix affine row node)
  · intro check
    by_contra failure
    have residual : PiopExtraction.linearResidual candidate.system check ≠ 0 :=
      sub_ne_zero.mpr failure
    obtain ⟨row, mismatch⟩ := detected.2 ⟨check, residual⟩
    exact mismatch (PiopExtraction.affine_batch_accepts_implies_linear_dot
      candidate.system (maskSum candidate) matrix affine row)

theorem accepted_piop_outside_named_algebraic_events_satisfies_candidate {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width)
    (response : ClaimedTranscript) (opening : Opening)
    (accepted : OpeningAccepts candidate matrix response opening)
    (rootDetection : DiscrepanciesDetected candidate matrix response opening)
    (residualDetection : ResidualsDetected candidate matrix) :
    PiopExtraction.FullySatisfied candidate.system := by
  obtain ⟨nonlinearZero, linearZero⟩ :=
    accepted_openings_force_actual_discrepancies_zero candidate matrix response opening accepted rootDetection
  exact detected_residuals_and_affine_checks_force_full_system candidate matrix
    (zero_discrepancies_force_affine_packing_checks candidate matrix response nonlinearZero linearZero)
    residualDetection

end
end HegemonCrypto.SmallWood.SmzaPiopGoodOutcome
