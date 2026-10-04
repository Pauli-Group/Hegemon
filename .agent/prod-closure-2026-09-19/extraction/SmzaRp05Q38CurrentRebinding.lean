import SmzaRp05CurrentCoset406
import SmzaRp05DecsPointProjection
import SmzaQ38OracleExtraction
import Mathlib.LinearAlgebra.Lagrange

/-!
# Current RP05 q38 evaluation-domain rebinding

The historical extraction module models 368 LVCS coordinates plus 20
openings. RP05 uses 368 coordinates plus 38 tails. This module preserves the
historical API while providing the current q38 geometry and evaluation map
for current-profile consumers.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05Q38CurrentRebinding

open HegemonCrypto.SmallWood
open HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406
open Polynomial

set_option autoImplicit false

noncomputable section

abbrev CommittedOracle := SmzaQ38OracleExtraction.CommittedOracle
abbrev decsDomainSize : Nat := SmzaQ38OracleExtraction.decsDomainSize
abbrev lvcsRowCount : Nat := SmzaQ38OracleExtraction.lvcsRowCount
abbrev relationRows : Nat := SmzaQ38OracleExtraction.relationRows
abbrev packingFactor : Nat := SmzaQ38OracleExtraction.packingFactor
abbrev unstackedRowCount : Nat := SmzaQ38OracleExtraction.unstackedRowCount
abbrev unstackedColumnCount : Nat := SmzaQ38OracleExtraction.unstackedColumnCount
def lvcsColumnCount : Nat := 368
def decsOpenedEvaluations : Nat := 38
def decsInterpolationPointCount : Nat := lvcsColumnCount + decsOpenedEvaluations

theorem current_extraction_geometry :
    decsDomainSize = 8388608 ∧ lvcsColumnCount = 368 ∧
      decsOpenedEvaluations = 38 ∧ decsInterpolationPointCount = 406 := by
  decide

abbrev smz9EvaluationPoint : Fin decsDomainSize → Goldilocks :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluationPoint

theorem smz9_evaluation_point_injective :
    Function.Injective smz9EvaluationPoint :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.evaluation_point_injective

theorem smz9_coset_disjoint_from_interpolation_domain
    (index : Fin decsDomainSize)
    (point : Fin decsInterpolationPointCount) :
    smz9EvaluationPoint index ≠ (point.val : Goldilocks) := by
  simpa [decsInterpolationPointCount] using
    HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.disjoint_from_interpolation_domain
      index point

theorem current_field_point_matches_source (index : Fin decsDomainSize) :
    SmzaRp05DecsPointProjection.fieldPoint 406 index.val =
      some (smz9EvaluationPoint index) := by
  simpa [decsDomainSize, smz9EvaluationPoint] using
    HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.source_field_point_is_current index

/-- The committed row payload is independent of the old coset choice. -/
abbrev committedColumnValue := SmzaQ38OracleExtraction.committedColumnValue

/-- Current RP05 row interpolation uses all 406 verifier nodes. -/
def interpolatedCommittedRow
    (oracle : CommittedOracle) (row : Fin lvcsRowCount) : Goldilocks[X] :=
  Lagrange.interpolate (Finset.univ : Finset (Fin decsDomainSize))
    smz9EvaluationPoint (committedColumnValue oracle row)

theorem interpolated_committed_row_eval
    (oracle : CommittedOracle) (row : Fin lvcsRowCount)
    (index : Fin decsDomainSize) :
    (interpolatedCommittedRow oracle row).eval (smz9EvaluationPoint index) =
      committedColumnValue oracle row index := by
  apply Lagrange.eval_interpolate_at_node
  · exact smz9_evaluation_point_injective.injOn
  · simp

/--
Current-map extraction theorem: any degree-at-most-405 polynomial agreeing
with the committed row on the current 2^23-point coset is exactly the row
interpolant used by RP05 extraction. This does not derive codeword agreement
from verifier acceptance.
-/
theorem interpolated_committed_row_eq_of_degree_405_codeword
    (oracle : CommittedOracle) (row : Fin lvcsRowCount)
    (polynomial : Goldilocks[X])
    (degreeBound : polynomial.degree < (decsInterpolationPointCount : WithBot Nat))
    (codewordAgreement : ∀ index : Fin decsDomainSize,
      polynomial.eval (smz9EvaluationPoint index) =
        committedColumnValue oracle row index) :
    interpolatedCommittedRow oracle row = polynomial := by
  have countLeDomain :
      (decsInterpolationPointCount : WithBot Nat) ≤ (decsDomainSize : WithBot Nat) := by
    norm_num [decsInterpolationPointCount, lvcsColumnCount, decsOpenedEvaluations,
      decsDomainSize, SmzaQ38OracleExtraction.decsDomainSize,
      HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsDomainSize]
  have degreeCard : polynomial.degree <
      ((Finset.univ : Finset (Fin decsDomainSize)).card : WithBot Nat) := by
    simpa using lt_of_lt_of_le degreeBound countLeDomain
  have recovered : polynomial =
      Lagrange.interpolate (Finset.univ : Finset (Fin decsDomainSize))
        smz9EvaluationPoint (committedColumnValue oracle row) :=
    Lagrange.eq_interpolate_of_eval_eq
      (r := committedColumnValue oracle row)
      (s := (Finset.univ : Finset (Fin decsDomainSize)))
      smz9_evaluation_point_injective.injOn degreeCard
      (fun index _ => codewordAgreement index)
  exact recovered.symm

/-- The current inverse rotation reserves the first 38 interpolation nodes. -/
def lvcsDataPoint (column : Fin lvcsColumnCount) : Goldilocks :=
  toGoldilocks (decsOpenedEvaluations + column.val)

/-- Current-map LVCS head read, with the source's 38-tail rotation. -/
def stackedHeadCell (oracle : CommittedOracle) (row : Fin lvcsRowCount)
    (column : Fin lvcsColumnCount) : Goldilocks :=
  (interpolatedCommittedRow oracle row).eval (lvcsDataPoint column)

abbrev stackedRowIndex := SmzaQ38OracleExtraction.stackedRowIndex
abbrev stackedColumnIndex := SmzaQ38OracleExtraction.stackedColumnIndex

def unstackedCell (oracle : CommittedOracle) (row : Fin unstackedRowCount)
    (column : Fin unstackedColumnCount) : Goldilocks :=
  stackedHeadCell oracle (stackedRowIndex row column) (stackedColumnIndex column)

abbrev witnessColumnIndex := SmzaQ38OracleExtraction.witnessColumnIndex

/-- Current-map, row-major degree-69 witness candidate for the existing relation. -/
def witnessPolynomial (oracle : CommittedOracle) (column : Fin relationRows) : Goldilocks[X] :=
  ∑ coefficient : Fin unstackedRowCount,
    C (unstackedCell oracle coefficient (witnessColumnIndex column)) * X ^ coefficient.val

theorem witness_polynomial_degree_le
    (oracle : CommittedOracle) (column : Fin relationRows) :
    (witnessPolynomial oracle column).natDegree ≤ 69 := by
  unfold witnessPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  have coefficientBound := coefficient.isLt
  change coefficient.val < 70 at coefficientBound
  change
    (C (unstackedCell oracle coefficient (witnessColumnIndex column))).natDegree +
      (X ^ coefficient.val).natDegree ≤ 69
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

abbrev witnessPackingPoint := SmzaQ38OracleExtraction.witnessPackingPoint
abbrev packedWitnessRowIndex := SmzaQ38OracleExtraction.packedWitnessRowIndex
abbrev packedWitnessLaneIndex := SmzaQ38OracleExtraction.packedWitnessLaneIndex

def extractPackedWitness (oracle : CommittedOracle) : List Nat :=
  List.ofFn fun index : Fin (relationRows * packingFactor) =>
    fromGoldilocks
      ((witnessPolynomial oracle (packedWitnessRowIndex index)).eval
        (witnessPackingPoint (packedWitnessLaneIndex index)))

theorem extract_packed_witness_length (oracle : CommittedOracle) :
    (extractPackedWitness oracle).length = relationRows * packingFactor := by
  simp only [extractPackedWitness, List.length_ofFn]

theorem literal_source_first_shift_and_leaf_zero :
    SmzaRp05DecsPointProjection.disjointCosetShift 406 = some (406 : Goldilocks) ∧
      SmzaRp05DecsPointProjection.fieldPoint 406 0 = some (406 : Goldilocks) := by
  constructor
  · exact HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.source_search_returns_406
  · have domainNonzero : SmzaRp05DecsPointProjection.domainSize ≠ 0 := by decide
    simp [SmzaRp05DecsPointProjection.fieldPoint, domainNonzero,
      HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.source_search_returns_406,
      HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406.cosetShift]

end
end HegemonCrypto.SmallWood.SmzaRp05Q38CurrentRebinding
