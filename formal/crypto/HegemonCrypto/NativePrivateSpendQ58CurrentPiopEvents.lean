import HegemonCrypto.NativePrivateSpendQ58CurrentOpeningDensity
import HegemonCrypto.NativePrivateSpendQ58CurrentDecodedRelation
import SmzaRp04ChronologicalAlgebra

/-! Actual current PIOP six-point algebra and finite events. No old Opening
is reinterpreted as current: all checks use the current predicate's six points.
The historical domain appears only in the proved injective cardinality lower
bound, weakened here to conservative1656. No414 counting campaign is required.
This does not assert that an arbitrary current verifier run supplies the scalar
checks; that separate same-execution bridge must derive them. SOURCE ONLY. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPiopEvents

open Polynomial V8Smz9PiopSoundness
open HegemonCrypto.SmallWoodPowerBatching
open V8Smz9AdaptiveFiniteAccounting
open V8Smz9AdaptiveFiniteAccounting.Historical
open V8Smz9RobustQueryMismatch
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Opening points)
end E
open E (points)
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- No extra PCS/legacy nonzero restrictions are current acceptance tests. -/
def CurrentOpeningChecks {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) (opening : E.Opening) : Prop :=
  ∀ row coordinate,
    (nonlinearDiscrepancy candidate matrix response row).eval (points opening coordinate) = 0 ∧
    (linearDiscrepancy candidate matrix response row).eval (points opening coordinate) = 0

def currentOpeningEvent {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript) : Finset E.Opening :=
  Finset.univ.filter (CurrentOpeningChecks candidate matrix response)

/-- Select the offending polynomial before examining any opening tuple.
The proof needs no historical Opening wrapper or detection callback. -/
theorem current_affine_failure_selects_fixed_nonzero_discrepancy {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width) (response : ClaimedTranscript)
    (failure : ¬ PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix) :
    ∃ polynomial : Goldilocks[X], polynomial ≠ 0 ∧ polynomial.natDegree ≤ 552 ∧
      ∀ opening : E.Opening, CurrentOpeningChecks candidate matrix response opening →
        ∀ coordinate, polynomial.eval (points opening coordinate) = 0 := by
  unfold PiopExtraction.AffineBatchAccepts at failure
  push Not at failure
  obtain ⟨row, failure⟩ := failure
  by_cases nonlinear : ∀ node ∈ candidate.system.nodes,
      (PiopExtraction.nonlinearBatch candidate.system (matrix row)).eval
        (candidate.system.point node) = 0
  · refine ⟨linearDiscrepancy candidate matrix response row,
      linear_discrepancy_ne_zero candidate matrix response row (failure nonlinear),
      (linear_discrepancy_degree candidate matrix response row).trans (by decide), ?_⟩
    intro opening checked coordinate
    exact (checked row coordinate).2
  · push Not at nonlinear
    obtain ⟨node, member, failed⟩ := nonlinear
    refine ⟨nonlinearDiscrepancy candidate matrix response row, ?_,
      nonlinear_discrepancy_degree candidate matrix response row, ?_⟩
    · exact PiopEvaluation.consistency_discrepancy_ne_zero_of_batch_failure
        (Finset.univ : Finset (Fin 64)) packingPoint _ _ _ node member failed
    · intro opening checked coordinate
      exact (checked row coordinate).1

/-- Same mathematical affine batching failure event; the current matrix
width is a parameter, not the old generated relation's width. -/
def currentMatrixEvent {width : Nat} (candidate : Candidate width) : Finset (Matrix width) :=
  PiopExtraction.affineBatchFailureSet candidate.system (maskSum candidate)

theorem current_matrix_probability {width : Nat} (candidate : Candidate width)
    (invalid : ¬ PiopExtraction.FullySatisfied candidate.system) :
    FiniteEvents.probability (currentMatrixEvent candidate) ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 := by
  exact PiopExtraction.unsatisfied_affine_batch_failure_probability_le
    candidate.system (maskSum candidate) invalid

/-- This conservative denominator is strictly weaker than the retained
cardinality lower bound. The only cross-domain operation is an embedding. -/
def conservativeCurrentDenominator : Nat :=
  distinctOutsideOpeningTupleCount - 1656 * goldilocksOrder ^ (piopOpenings - 1)

theorem conservative_current_denominator_positive :
    0 < conservativeCurrentDenominator := by
  decide

theorem conservative_denominator_le_current_card :
    conservativeCurrentDenominator ≤ Fintype.card E.Opening := by
  apply (show conservativeCurrentDenominator ≤ correctionAwareOpeningTupleLowerBound from ?_).trans
    NativePrivateSpendQ58CurrentOpeningDensity.current_opening_card_lower_bound
  unfold conservativeCurrentDenominator correctionAwareOpeningTupleLowerBound
    admissibilityRejectedTupleUpperBound
  apply Nat.sub_le_sub_left
  apply Nat.mul_le_mul_right
  rw [exact_opening_admissibility_bad_tuple_coefficient]
  decide

theorem current_opening_card_positive : 0 < Fintype.card E.Opening :=
  conservative_current_denominator_positive.trans_le conservative_denominator_le_current_card

/-- Cardinality of the current accepted root event, with no old Opening cast. -/
theorem current_opening_event_card {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript)
    (failure : ¬ PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix) :
    (currentOpeningEvent candidate matrix response).card ≤ fallingProduct 552 piopOpenings := by
  obtain ⟨polynomial, nonzero, bounded, contained⟩ :=
    current_affine_failure_selects_fixed_nonzero_discrepancy candidate matrix response failure
  let embedding : { opening // opening ∈ currentOpeningEvent candidate matrix response } ↪
      NativePrivateSpendQ58CurrentOpeningDensity.CurrentRootTuple polynomial :=
    { toFun := fun opening => ⟨opening.val,
        contained opening.val ((Finset.mem_filter.mp opening.property).2)⟩
      inj' := by
        intro left right same
        apply Subtype.ext
        exact congrArg
          (fun root : NativePrivateSpendQ58CurrentOpeningDensity.CurrentRootTuple polynomial =>
            root.val) same }
  have count : (currentOpeningEvent candidate matrix response).card ≤
      Fintype.card (NativePrivateSpendQ58CurrentOpeningDensity.CurrentRootTuple polynomial) := by
    simpa only [Fintype.card_coe] using Fintype.card_le_of_embedding embedding
  apply (count.trans
    (NativePrivateSpendQ58CurrentOpeningDensity.current_root_tuple_card_le nonzero)).trans
  change Hegemon.Transaction.SmallWoodNoGrindingSoundness.fallingProduct
      polynomial.natDegree piopOpenings ≤
    Hegemon.Transaction.SmallWoodNoGrindingSoundness.fallingProduct 552 piopOpenings
  simp only [UniformSubsetSampling.falling_product_eq_desc_factorial]
  exact Nat.descFactorial_le _ bounded

/-- Genuine current-domain conditional probability. No probability or density
assumption is supplied; the sample space and numerator are counted directly. -/
theorem current_opening_probability {width : Nat} (candidate : Candidate width)
    (matrix : Matrix width) (response : ClaimedTranscript)
    (failure : ¬ PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix) :
    FiniteEvents.probability (currentOpeningEvent candidate matrix response) ≤
      (fallingProduct 552 piopOpenings : Rat) / conservativeCurrentDenominator := by
  unfold FiniteEvents.probability
  apply (div_le_div_iff₀
    (by exact_mod_cast current_opening_card_positive)
    (by exact_mod_cast conservative_current_denominator_positive)).mpr
  exact_mod_cast (Nat.mul_le_mul_right conservativeCurrentDenominator
    (current_opening_event_card candidate matrix response failure)).trans
      (Nat.mul_le_mul_left (fallingProduct 552 piopOpenings)
        conservative_denominator_le_current_card)

/-- Honest finite good/bad split after actual scalar checks have been DERIVED.
No detection predicate or desired relation-satisfaction premise is accepted. -/
theorem current_opened_candidate_is_valid_or_matrix_or_fixed_root {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width) (response : ClaimedTranscript)
    (opening : E.Opening) (checked : CurrentOpeningChecks candidate matrix response opening) :
    PiopExtraction.FullySatisfied candidate.system ∨
    (¬ PiopExtraction.FullySatisfied candidate.system ∧ matrix ∈ currentMatrixEvent candidate) ∨
    ∃ polynomial : Goldilocks[X], polynomial ≠ 0 ∧ polynomial.natDegree ≤ 552 ∧
      ∀ coordinate, polynomial.eval (points opening coordinate) = 0 := by
  by_cases satisfied : PiopExtraction.FullySatisfied candidate.system
  · exact Or.inl satisfied
  · by_cases affine : PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix
    · exact Or.inr (Or.inl ⟨satisfied, Finset.mem_filter.mpr ⟨Finset.mem_univ _, affine⟩⟩)
    · obtain ⟨polynomial, nonzero, bounded, root⟩ :=
        current_affine_failure_selects_fixed_nonzero_discrepancy candidate matrix response affine
      exact Or.inr (Or.inr ⟨polynomial, nonzero, bounded, root opening checked⟩)

/-- Applies the proved current packed-relation interpretation, preserving the
literal matrix/root alternatives instead of assuming them excluded. -/
theorem current_decoded_openings_have_witness_or_named_piop_events
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (source : NativePrivateSpendQ58CurrentDecodedRelation.Decoded)
    (matrix : Matrix 1344594) (response : ClaimedTranscript) (opening : E.Opening)
    (checked : CurrentOpeningChecks
      (NativePrivateSpendQ58CurrentDecodedRelation.candidate relation source)
      matrix response opening) :
    NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation
      (NativePrivateSpendQ58CurrentDecodedRelation.decodedValues source) ∨
    (¬ PiopExtraction.FullySatisfied
      (NativePrivateSpendQ58CurrentDecodedRelation.candidate relation source).system ∧
      matrix ∈ currentMatrixEvent
        (NativePrivateSpendQ58CurrentDecodedRelation.candidate relation source)) ∨
    ∃ polynomial : Goldilocks[X], polynomial ≠ 0 ∧ polynomial.natDegree ≤ 552 ∧
      ∀ coordinate, polynomial.eval (points opening coordinate) = 0 := by
  rcases current_opened_candidate_is_valid_or_matrix_or_fixed_root
    (NativePrivateSpendQ58CurrentDecodedRelation.candidate relation source)
    matrix response opening checked with satisfied | bad
  · exact Or.inl (NativePrivateSpendQ58CurrentDecodedRelation.fully_satisfied_implies_current_relation
      relation source satisfied)
  · exact Or.inr bad

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPiopEvents
