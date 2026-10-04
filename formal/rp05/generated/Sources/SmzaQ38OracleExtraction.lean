import HegemonCrypto.SmallWoodV8Smz9DisjointCoset
import HegemonCrypto.SmallWoodV8Smz9LogicalOracle
import HegemonCrypto.Poseidon2V8ExpressionRootSemantics
import Hegemon.Transaction.Poseidon2V8ConstraintRefinement
import Mathlib.Data.List.OfFn
import Mathlib.LinearAlgebra.Lagrange

set_option maxHeartbeats 800000
set_option maxRecDepth 10000

/-!
# Q38 deterministic candidate inverse

This additive model reads data heads at 38..405, never the q20 20..387 offset.
The committed table dimensions and disjoint-coset evaluation map are unchanged.
Full-table interpolation is a candidate inverse, not an error-correcting decoder.
No acceptance, extraction success, or probability bound is assumed or concluded.
-/

namespace HegemonCrypto.SmallWood.SmzaQ38OracleExtraction

open Polynomial
open HegemonCrypto.SmallWood
open HegemonCrypto.SmallWood.V8Smz9DisjointCoset
open HegemonCrypto.SmallWood.V8Smz9LogicalOracle
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

noncomputable section

abbrev CommittedOracle := V8Smz9LogicalOracle.CommittedOracle
abbrev RelationProgramComponents :=
  Hegemon.Transaction.Poseidon2V8RelationProgram.RelationProgramComponents

def relationRows : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationRowCount
def packingFactor : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor
def decsDomainSize : Nat := V8Smz9LogicalOracle.decsDomainSize
def decsOpenedEvaluations : Nat := 38
def unstackedRowCount : Nat := packingFactor + V8Smz9LogicalOracle.piopOpeningCount
def unstackedColumnCount : Nat := 736
def lvcsRowCount : Nat := V8Smz9LogicalOracle.decsRowCount
def lvcsColumnCount : Nat :=
  Hegemon.Transaction.Poseidon2V8ConstraintRefinement.proofGeometryColumnCount
def decsInterpolationPointCount : Nat :=
  lvcsColumnCount + decsOpenedEvaluations

theorem exact_extraction_geometry :
    relationRows = 686 ∧ packingFactor = 64 ∧ decsDomainSize = 8388608 ∧
      decsOpenedEvaluations = 38 ∧ unstackedRowCount = 70 ∧
      unstackedColumnCount = 736 ∧ lvcsRowCount = 140 ∧
      lvcsColumnCount = 368 ∧ decsInterpolationPointCount = 406 := by
  decide

/-! ## Exact production disjoint coset -/

abbrev smz9EvaluationPoint : Fin decsDomainSize → Goldilocks :=
  V8Smz9DisjointCoset.evaluationPoint

theorem smz9_evaluation_point_injective :
    Function.Injective smz9EvaluationPoint :=
  V8Smz9DisjointCoset.evaluation_point_injective

/-! ## Inverse LVCS stacking and exact 686-by-64 witness -/

def wordToGoldilocks (word : V8Smz9LogicalOracle.FieldWord) : Goldilocks :=
  toGoldilocks word.val

/-- One of the first 140, non-masking columns of the exact committed oracle. -/
def committedColumnValue
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount)
    (index : Fin decsDomainSize) : Goldilocks :=
  wordToGoldilocks
    (oracle index ⟨row.val, by
      have rowBound := row.isLt
      change row.val < 140 at rowBound
      change row.val < 140 + 5
      omega⟩)

/-- Canonical interpolation of one committed LVCS row over the exact production coset. -/
def interpolatedCommittedRow
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount) : Goldilocks[X] :=
  Lagrange.interpolate
    (Finset.univ : Finset (Fin decsDomainSize))
    smz9EvaluationPoint
    (committedColumnValue oracle row)

theorem interpolated_committed_row_eval
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount)
    (index : Fin decsDomainSize) :
    (interpolatedCommittedRow oracle row).eval (smz9EvaluationPoint index) =
      committedColumnValue oracle row index := by
  apply Lagrange.eval_interpolate_at_node
  · exact smz9_evaluation_point_injective.injOn
  · simp

/--
The candidate interpolation really recovers a polynomial of degree at most 405 when the committed
row agrees with it on every domain point.  The premise is full pointwise codeword agreement, not
the desired program-acceptance conclusion; deriving it (or an error-correctable proximity version)
from verifier acceptance remains the cryptographic soundness obligation.
-/
theorem interpolated_committed_row_eq_of_degree_405_codeword
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount)
    (polynomial : Goldilocks[X])
    (degreeBound : polynomial.degree < (decsInterpolationPointCount : WithBot Nat))
    (codewordAgreement : ∀ index : Fin decsDomainSize,
      polynomial.eval (smz9EvaluationPoint index) =
        committedColumnValue oracle row index) :
    interpolatedCommittedRow oracle row = polynomial := by
  have interpolationCountLeDomain :
      (decsInterpolationPointCount : WithBot Nat) ≤ (decsDomainSize : WithBot Nat) := by
    norm_num [decsInterpolationPointCount, lvcsColumnCount, decsOpenedEvaluations,
      decsDomainSize, V8Smz9LogicalOracle.decsDomainSize,
      V8Smz9LogicalOracle.decsOpeningCount,
      Hegemon.Transaction.Poseidon2V8ConstraintRefinement.proofGeometryColumnCount]
  have degreeCard :
      polynomial.degree <
        ((Finset.univ : Finset (Fin decsDomainSize)).card : WithBot Nat) := by
    simpa using lt_of_lt_of_le degreeBound interpolationCountLeDomain
  have recovered :
      polynomial =
        Lagrange.interpolate (Finset.univ : Finset (Fin decsDomainSize))
          smz9EvaluationPoint (committedColumnValue oracle row) :=
    Lagrange.eq_interpolate_of_eval_eq
      (r := committedColumnValue oracle row)
      (s := (Finset.univ : Finset (Fin decsDomainSize)))
      smz9_evaluation_point_injective.injOn degreeCard
      (fun index _ => codewordAgreement index)
  exact recovered.symm

/-- The inverse rotation reads the 368 data cells at interpolation points `38 .. 405`. -/
def lvcsDataPoint (column : Fin lvcsColumnCount) : Goldilocks :=
  toGoldilocks (decsOpenedEvaluations + column.val)

def stackedHeadCell
    (oracle : CommittedOracle)
    (row : Fin lvcsRowCount)
    (column : Fin lvcsColumnCount) : Goldilocks :=
  (interpolatedCommittedRow oracle row).eval (lvcsDataPoint column)

/-- Stacked row containing one cell of the exact `70 x 736` unstacked matrix. -/
def stackedRowIndex
    (row : Fin unstackedRowCount)
    (column : Fin unstackedColumnCount) : Fin lvcsRowCount :=
  ⟨(column.val / lvcsColumnCount) * unstackedRowCount + row.val, by
    have rowBound := row.isLt
    have columnBound := column.isLt
    change row.val < 70 at rowBound
    change column.val < 736 at columnBound
    change (column.val / 368) * 70 + row.val < 140
    have blockBound : column.val / 368 < 2 := by omega
    omega⟩

/-- Column inside the 368-cell stacked row containing one unstacked cell. -/
def stackedColumnIndex
    (column : Fin unstackedColumnCount) : Fin lvcsColumnCount :=
  ⟨column.val % lvcsColumnCount, Nat.mod_lt _ (by decide)⟩

def unstackedCell
    (oracle : CommittedOracle)
    (row : Fin unstackedRowCount)
    (column : Fin unstackedColumnCount) : Goldilocks :=
  stackedHeadCell oracle (stackedRowIndex row column) (stackedColumnIndex column)

/-- Embed one of the 686 witness-polynomial columns in the 736-column matrix. -/
def witnessColumnIndex (column : Fin relationRows) : Fin unstackedColumnCount :=
  ⟨column.val, by
    have columnBound := column.isLt
    change column.val < 686 at columnBound
    change column.val < 736
    omega⟩

/-- Candidate degree-69 polynomial produced for one HGV8RP03 witness row. -/
def witnessPolynomial
    (oracle : CommittedOracle)
    (column : Fin relationRows) : Goldilocks[X] :=
  ∑ coefficient : Fin unstackedRowCount,
    C (unstackedCell oracle coefficient (witnessColumnIndex column)) *
      X ^ coefficient.val

theorem witness_polynomial_degree_le
    (oracle : CommittedOracle)
    (column : Fin relationRows) :
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

def packedWitnessRowIndex
    (index : Fin (relationRows * packingFactor)) : Fin relationRows :=
  ⟨index.val / packingFactor, by
    have indexBound := index.isLt
    change index.val < 686 * 64 at indexBound
    change index.val / 64 < 686
    omega⟩

def packedWitnessLaneIndex
    (index : Fin (relationRows * packingFactor)) : Fin packingFactor :=
  ⟨index.val % packingFactor, Nat.mod_lt _ (by decide)⟩

def witnessPackingPoint (lane : Fin packingFactor) : Goldilocks :=
  toGoldilocks lane.val

/-- One deterministic, canonical field word of the extracted row-major witness. -/
def extractPackedWitnessCell
    (oracle : CommittedOracle)
    (index : Fin (relationRows * packingFactor)) : Nat :=
  fromGoldilocks
    ((witnessPolynomial oracle (packedWitnessRowIndex index)).eval
      (witnessPackingPoint (packedWitnessLaneIndex index)))

/-- Exact packed witness list consumed by `RelationProgramComponents.AcceptsPacked`. -/
def extractPackedWitness (oracle : CommittedOracle) : List Nat :=
  List.ofFn (extractPackedWitnessCell oracle)

theorem extract_packed_witness_length (oracle : CommittedOracle) :
    (extractPackedWitness oracle).length =
      Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessWordCount := by
  simp [extractPackedWitness, relationRows, packingFactor,
    Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationRowCount,
    Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
    Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessWordCount]

theorem extract_packed_witness_getD
    (oracle : CommittedOracle)
    (index : Nat)
    (indexBound : index < relationRows * packingFactor) :
    (extractPackedWitness oracle).getD index 0 =
      extractPackedWitnessCell oracle ⟨index, indexBound⟩ := by
  have withinList : index < (extractPackedWitness oracle).length := by
    simpa [extractPackedWitness] using indexBound
  rw [List.getD_eq_getElem _ _ withinList]
  simp [extractPackedWitness]

theorem extract_packed_witness_is_canonical (oracle : CommittedOracle) :
    CanonicalPackedWitness (extractPackedWitness oracle) := by
  constructor
  · exact extract_packed_witness_length oracle
  · rw [extractPackedWitness, List.forall_mem_ofFn_iff]
    intro index
    exact fromGoldilocks_lt _

/-- The 686 candidate-polynomial evaluations supplied to one nonlinear interpreter lane. -/
def extractedWitnessLaneRows
    (oracle : CommittedOracle)
    (lane : Fin packingFactor) : List Nat :=
  List.ofFn fun row : Fin relationRows =>
    fromGoldilocks ((witnessPolynomial oracle row).eval (witnessPackingPoint lane))

theorem packed_witness_lane_rows_getElem
    (packedWitness : List Nat)
    (lane row : Nat)
    (rowBound : row < (packedWitnessLaneRows packedWitness lane).length) :
    (packedWitnessLaneRows packedWitness lane)[row] =
      packedWitness.getD
        (row * Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor + lane) 0 := by
  simp [packedWitnessLaneRows]

theorem extracted_witness_lane_rows_getElem
    (oracle : CommittedOracle)
    (lane : Fin packingFactor)
    (row : Nat)
    (rowBound : row < relationRows)
    (listBound : row < (extractedWitnessLaneRows oracle lane).length) :
    (extractedWitnessLaneRows oracle lane)[row] =
      fromGoldilocks
        ((witnessPolynomial oracle ⟨row, rowBound⟩).eval
          (witnessPackingPoint lane)) := by
  simp [extractedWitnessLaneRows]

theorem packed_witness_lane_rows_of_extraction
    (oracle : CommittedOracle)
    (lane : Fin packingFactor) :
    packedWitnessLaneRows (extractPackedWitness oracle) lane.val =
      extractedWitnessLaneRows oracle lane := by
  apply List.ext_getElem
  · rw [packed_witness_lane_rows_have_exact_relation_length]
    change
      Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount = relationRows
    rfl
  · intro index leftBound rightBound
    have rowBound : index < relationRows := by
      simpa [extractedWitnessLaneRows] using rightBound
    have laneBound := lane.isLt
    have flatBound : index * packingFactor + lane.val < relationRows * packingFactor := by
      change index < 686 at rowBound
      change lane.val < 64 at laneBound
      change index * 64 + lane.val < 686 * 64
      omega
    rw [packed_witness_lane_rows_getElem]
    rw [extracted_witness_lane_rows_getElem oracle lane index rowBound rightBound]
    change
      (extractPackedWitness oracle).getD (index * packingFactor + lane.val) 0 = _
    rw [extract_packed_witness_getD oracle _ flatBound]
    unfold extractPackedWitnessCell
    have laneBoundExact : lane.val < 64 := by
      exact lane.isLt
    have rowEquation :
        packedWitnessRowIndex
            ⟨index * packingFactor + lane.val, flatBound⟩ =
          ⟨index, rowBound⟩ := by
      apply Fin.ext
      change (index * 64 + lane.val) / 64 = index
      omega
    have laneEquation :
        packedWitnessLaneIndex
            ⟨index * packingFactor + lane.val, flatBound⟩ = lane := by
      apply Fin.ext
      change (index * 64 + lane.val) % 64 = lane.val
      omega
    rw [rowEquation, laneEquation]

/-!
Program satisfaction stated directly over the candidate polynomials derived from the committed
oracle table.  The CSR half intentionally retains the full row-major list because the executable
CSR grammar addresses any of its 43,904 words.
-/
def ExtractedProgramSatisfied
    (components : RelationProgramComponents)
    (publicWords : List Nat)
    (oracle : CommittedOracle) : Prop :=
  CanonicalPublicWords publicWords ∧
    (∀ lane : Fin packingFactor,
      components.nonlinearExecutable.Accepts publicWords
        (extractedWitnessLaneRows oracle lane)) ∧
    csrExecutableProgramAccepts components.csrExpressions components.csrAttempts
      publicWords (extractPackedWitness oracle)

/--
Exact representation equivalence between satisfaction over the candidate polynomials and
`AcceptsPacked` for their row-major materialization.  Canonicality of all 43,904 materialized
words is proved rather than requested from a future knowledge extractor.  This theorem does not
derive either side from verifier acceptance or from a DECS proximity premise.
-/
theorem extracted_program_satisfied_iff_accepts_packed
    (components : RelationProgramComponents)
    (publicWords : List Nat)
    (oracle : CommittedOracle) :
    ExtractedProgramSatisfied components publicWords oracle ↔
      components.AcceptsPacked publicWords (extractPackedWitness oracle) := by
  constructor
  · rintro ⟨canonicalPublic, nonlinear, csr⟩
    refine ⟨canonicalPublic, extract_packed_witness_is_canonical oracle, ?_, csr⟩
    intro lane laneBound
    let finiteLane : Fin packingFactor := ⟨lane, laneBound⟩
    rw [packed_witness_lane_rows_of_extraction oracle finiteLane]
    exact nonlinear finiteLane
  · intro accepted
    refine ⟨accepted.1, ?_, accepted.2.2.2⟩
    intro lane
    rw [← packed_witness_lane_rows_of_extraction oracle lane]
    exact accepted.2.2.1 lane.val lane.isLt

/-! ## First executable semantic consequence -/

/--
For every lane materialized from the candidate inverse, every named nonlinear identity in the
chosen program components has an interpreter trace whose root is zero.  This is an interpreter
semantic consequence of `ExtractedProgramSatisfied`, not a derivation from verifier acceptance.
-/
theorem extracted_program_satisfaction_makes_each_nonlinear_root_zero
    {components : RelationProgramComponents}
    {publicWords : List Nat}
    {oracle : CommittedOracle}
    (satisfied : ExtractedProgramSatisfied components publicWords oracle)
    (lane : Fin packingFactor)
    {root : Nat}
    (rootMembership : root ∈ components.nonlinearExecutable.roots) :
    ∃ values,
      evalExpressionNodes publicWords (extractedWitnessLaneRows oracle lane)
          components.nonlinearExecutable.expressions = some values ∧
        values[root]? = some 0 := by
  exact acceptance_makes_each_named_root_zero
    (satisfied.2.1 lane) rootMembership

end

end HegemonCrypto.SmallWood.SmzaQ38OracleExtraction
