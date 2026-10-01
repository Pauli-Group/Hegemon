import SmzaRp05RelationDslBase
import SmzaRp05AcceptedRelationInterface
import SmzaRp04ActualProgram
import SmzaRp04DecodedPolynomialSource

/-!
# Structural RP05 relation refinement

The accepted-extraction theorem needs two implications which must not be
postulated as endpoint assumptions.  This file derives both for any instance
of the executable relation DSL.  A generated RP05 artifact supplies only two
finite certificates:

1. `NonlinearCertificate`: the executable nonlinear roots are exactly the
   indexed polynomial roots, the expression DAG is canonical, and its checked
   node-degree interpretation gives root degree at most eight;
2. `CsrCertificate`: the public CSR expression DAG and attempt coordinates are
   canonical, and each raw executable attempt is identified coefficient by
   coefficient with one retained normalized row, or is certified to be the
   discarded equation `0 = 0`, or is an impossible-empty row routed through
   the independently constrained zero source cell exactly as in Rust.

For the current artifact these certificates must compute with exactly 818
nonlinear roots.  The generic proof keeps the fixed source geometry of 686
witness rows and 64 packing lanes, but does not use the RP04 program or its
773-wide nonlinear family.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05RelationRefinement

open Polynomial
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp05StatementNamespace SmzaRp05TracePrefixes
open SmzaRp05AcceptedExtraction
open SmzaQ38Recovery SmzaQ38OpeningFieldReadback SmzaQ38LvcsOpening
open SmzaRp04DecodedPolynomialSource
open V8Smz9ProgramPolynomials V8Smz9CurrentSourceAcceptance
open V8Smz9CurrentPublicContext V8Smz9CurrentProgramOpeningBinding
open V8Smz9PiopOpeningRecovery V8Smz9PiopSoundness
open V8Smz9AdaptiveFiniteAccounting V8Smz9EagerSimulator
open V8Smz9EagerPrivacy V8Smz9ZeroKnowledge
open V8Smz9SemanticDenseRange
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "packingPoint" => V8Smz9EagerSimulator.canonicalPacking
local notation "packingPoint_injective" =>
  V8Smz9DecodedPolynomialSource.canonical_packing_injective

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

/-- The old namespace contains this q38 coordinate adapter, but the definition
is relation-independent: it only translates heads 20+j to q38 heads 38+j. -/
def sourceOfRows (rows : RecoveredRows) : SourcePolynomials :=
  SmzaRp04ActualProgram.headCoordinateAdapter rows

def witnessPolynomialAtNat (source : SourcePolynomials) (row : Nat) : Goldilocks[X] :=
  if bound : row < 686 then witnessPolynomials source ⟨row, bound⟩ else 0

def witnessFieldAtNat (witness : Fin 686 → Goldilocks) : Nat → Goldilocks :=
  V8Smz9EagerSimulator.openedWitnessAtNat witness

def publicFieldAtNat (statement : Statement) (word : Nat) : Goldilocks :=
  (currentPublicWords statement).getD word 0

def nonlinearPolynomial (dsl : RelationDsl) (statement : Statement)
    (source : SourcePolynomials) (root : Fin dsl.nonlinearCount) : Goldilocks[X] :=
  polynomialAt dsl.components.nonlinearExecutable.expressions
    (publicFieldAtNat statement) (witnessPolynomialAtNat source)
    (dsl.nonlinearRoot root)

def nonlinearScalar (dsl : RelationDsl) (statement : Statement)
    (witness : Fin 686 → Goldilocks) (root : Fin dsl.nonlinearCount) : Goldilocks :=
  fieldAt dsl.components.nonlinearExecutable.expressions
    (publicFieldAtNat statement) (witnessFieldAtNat witness)
    (dsl.nonlinearRoot root)

def linearPolynomial (dsl : RelationDsl) (statement : Statement)
    (source : SourcePolynomials) (row : Fin (dsl.linearCount statement)) : Goldilocks[X] :=
  sourceLinearUnmasked (dsl.linearWeights statement row)
    (sourcePackingLagrange packingPoint) (witnessPolynomials source)

def linearScalar (dsl : RelationDsl) (statement : Statement)
    (witness : Fin 686 → Goldilocks) (point : Goldilocks)
    (row : Fin (dsl.linearCount statement)) : Goldilocks :=
  publicLinearOpening (dsl.linearWeights statement row)
    (sourcePackingLagrange packingPoint) witness point

theorem witness_polynomial_at_nat_degree (source : SourcePolynomials) (row : Nat) :
    (witnessPolynomialAtNat source row).natDegree ≤ 69 := by
  unfold witnessPolynomialAtNat
  split
  · exact witness_polynomials_degree source _
  · simp

theorem nonlinear_polynomial_degree (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (source : SourcePolynomials) (root : Fin dsl.nonlinearCount) :
    (nonlinearPolynomial dsl statement source root).natDegree ≤ 552 := by
  have degree := polynomialAt_degree dsl.components.nonlinearExecutable.expressions
    dsl.nodeDegree certificates.nonlinear.degreeCertificate
    (publicFieldAtNat statement) (witnessPolynomialAtNat source) 69
    (witness_polynomial_at_nat_degree source) (dsl.nonlinearRoot root)
  exact degree.trans (by
    have rootDegree := certificates.nonlinear.rootDegree root
    omega)

theorem nonlinear_polynomial_evaluation (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (source : SourcePolynomials) (root : Fin dsl.nonlinearCount)
    (point : Goldilocks) :
    (nonlinearPolynomial dsl statement source root).eval point =
      nonlinearScalar dsl statement
        (fun row => (witnessPolynomials source row).eval point) root := by
  have rowsEqual :
      (fun row => (witnessPolynomialAtNat source row).eval point) =
        witnessFieldAtNat (fun row => (witnessPolynomials source row).eval point) := by
    funext row
    unfold witnessPolynomialAtNat witnessFieldAtNat
      V8Smz9EagerSimulator.openedWitnessAtNat
    split <;> simp_all
  simpa only [nonlinearPolynomial, nonlinearScalar, rowsEqual] using
    (polynomialAt_commutes dsl.components.nonlinearExecutable.expressions
      dsl.nodeDegree certificates.nonlinear.degreeCertificate
      (publicFieldAtNat statement) (witnessPolynomialAtNat source) 69
      (witness_polynomial_at_nat_degree source) (dsl.nonlinearRoot root) point)

theorem linear_polynomial_degree (dsl : RelationDsl) (statement : Statement)
    (source : SourcePolynomials) (row : Fin (dsl.linearCount statement)) :
    (linearPolynomial dsl statement source row).natDegree ≤ 132 := by
  exact source_linear_unmasked_degree packingPoint packingPoint_injective
    (dsl.linearWeights statement row) (witnessPolynomials source)
    (witness_polynomials_degree source)

theorem linear_polynomial_evaluation (dsl : RelationDsl) (statement : Statement)
    (source : SourcePolynomials) (row : Fin (dsl.linearCount statement))
    (point : Goldilocks) :
    (linearPolynomial dsl statement source row).eval point =
      linearScalar dsl statement
        (fun witnessRow => (witnessPolynomials source witnessRow).eval point)
        point row := by
  exact source_linear_unmasked_evaluation (dsl.linearWeights statement row)
    (sourcePackingLagrange packingPoint) (witnessPolynomials source) point

def paddedNonlinear (dsl : RelationDsl) (statement : Statement) (source : SourcePolynomials)
    (check : Fin (dsl.width statement)) : Goldilocks[X] :=
  if bound : check.val < dsl.nonlinearCount then
    nonlinearPolynomial dsl statement source ⟨check.val, bound⟩
  else 0

def paddedNonlinearScalar (dsl : RelationDsl) (statement : Statement)
    (witness : Fin 686 → Goldilocks) (check : Fin (dsl.width statement)) : Goldilocks :=
  if bound : check.val < dsl.nonlinearCount then
    nonlinearScalar dsl statement witness ⟨check.val, bound⟩
  else 0

def paddedLinear (dsl : RelationDsl) (statement : Statement)
    (source : SourcePolynomials) (check : Fin (dsl.width statement)) : Goldilocks[X] :=
  if bound : check.val < dsl.linearCount statement then
    linearPolynomial dsl statement source ⟨check.val, bound⟩
  else 0

def paddedLinearScalar (dsl : RelationDsl) (statement : Statement)
    (witness : Fin 686 → Goldilocks) (point : Goldilocks)
    (check : Fin (dsl.width statement)) : Goldilocks :=
  if bound : check.val < dsl.linearCount statement then
    linearScalar dsl statement witness point ⟨check.val, bound⟩
  else 0

def paddedTarget (dsl : RelationDsl) (statement : Statement)
    (check : Fin (dsl.width statement)) : Goldilocks :=
  if bound : check.val < dsl.linearCount statement then
    dsl.linearTarget statement ⟨check.val, bound⟩
  else 0

/-- Candidate built directly from the generated expression DAG and normalized
CSR rows. -/
def candidate (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows) : Candidate (dsl.width statement) :=
  let source := sourceOfRows rows
  { nonlinear := paddedNonlinear dsl statement source
    linear := paddedLinear dsl statement source
    target := paddedTarget dsl statement
    nonlinearMask := nonlinearMasks source
    linearMask := linearMasks source
    nonlinearDegree := by
      intro check
      unfold paddedNonlinear
      split
      · exact nonlinear_polynomial_degree dsl certificates statement source _
      · simp
    linearDegree := by
      intro check
      unfold paddedLinear
      split
      · exact linear_polynomial_degree dsl statement source _
      · simp
    nonlinearMaskDegree := nonlinear_masks_degree source
    linearMaskDegree := linear_masks_degree source }

def relationModel (dsl : RelationDsl) (certificates : GeneratedCertificates dsl) :
    RelationModel where
  width := dsl.width
  recoveredCandidate := candidate dsl certificates

theorem candidate_nonlinear_evaluation (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (rows : RecoveredRows) (check : Fin (dsl.width statement)) (point : Goldilocks) :
    ((candidate dsl certificates statement rows).nonlinear check).eval point =
      paddedNonlinearScalar dsl statement
        (fun row => (recoveredWitnessPolynomial rows row).eval point) check := by
  by_cases bound : check.val < dsl.nonlinearCount
  · simp only [candidate, paddedNonlinear, paddedNonlinearScalar, dif_pos bound]
    rw [nonlinear_polynomial_evaluation dsl certificates statement
      (sourceOfRows rows) ⟨check.val, bound⟩ point]
    simp only [sourceOfRows,
      SmzaRp04ActualProgram.adapted_witness_polynomial_is_exact_q38]
  · simp only [candidate, paddedNonlinear, paddedNonlinearScalar, dif_neg bound, eval_zero]

theorem candidate_linear_evaluation (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (rows : RecoveredRows) (check : Fin (dsl.width statement)) (point : Goldilocks) :
    ((candidate dsl certificates statement rows).linear check).eval point =
      paddedLinearScalar dsl statement
        (fun row => (recoveredWitnessPolynomial rows row).eval point) point check := by
  by_cases bound : check.val < dsl.linearCount statement
  · simp only [candidate, paddedLinear, paddedLinearScalar, dif_pos bound]
    rw [linear_polynomial_evaluation]
    simp only [sourceOfRows,
      SmzaRp04ActualProgram.adapted_witness_polynomial_is_exact_q38]
  · simp only [candidate, paddedLinear, paddedLinearScalar, dif_neg bound, eval_zero]

theorem source_column_is_recovered_column (rows : RecoveredRows) (column : Fin 736) :
    columnPolynomial (sourceOfRows rows) column = recoveredColumn rows column :=
  SmzaRp04ScalarCheckTransport.adapted_column_polynomial_is_recovered_column rows column

theorem candidate_nonlinear_mask_evaluation (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (rows : RecoveredRows) (row : Fin 5) (point : Goldilocks) :
    ((candidate dsl certificates statement rows).nonlinearMask row).eval point =
      SmzaQ38OpeningFieldReadback.nonlinearScalar point
        (fun column => (recoveredColumn rows column).eval point) row := by
  change (nonlinearMasks (sourceOfRows rows) row).eval point = _
  rw [nonlinear_masks_evaluate]
  unfold SmzaQ38OpeningFieldReadback.nonlinearScalar
  apply congrArg (sourceNonlinearReconstruction point)
  funext column
  change (columnPolynomial (sourceOfRows rows)
    (Fin.natAdd 686 (Fin.castAdd 10 (finProdFinEquiv (row, column))))).eval point = _
  rw [source_column_is_recovered_column]

theorem candidate_linear_mask_evaluation (dsl : RelationDsl)
    (certificates : GeneratedCertificates dsl) (statement : Statement)
    (rows : RecoveredRows) (row : Fin 5) (point : Goldilocks) :
    ((candidate dsl certificates statement rows).linearMask row).eval point =
      SmzaQ38OpeningFieldReadback.linearScalar point
        (fun column => (recoveredColumn rows column).eval point) row := by
  change (linearMasks (sourceOfRows rows) row).eval point = _
  rw [linear_masks_evaluate]
  change
    (columnPolynomial (sourceOfRows rows)
      (Fin.natAdd 686 (Fin.natAdd 40 (finProdFinEquiv (row, (0 : Fin 2)))))).eval point +
    point ^ 63 * (columnPolynomial (sourceOfRows rows)
      (Fin.natAdd 686 (Fin.natAdd 40 (finProdFinEquiv (row, (1 : Fin 2)))))).eval point = _
  simp only [source_column_is_recovered_column,
    SmzaQ38OpeningFieldReadback.linearScalar]

/-- These are the actual scalar equations checked after the six openings. -/
def ScalarChecks (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (matrix : Matrix (dsl.width statement)) (response : ClaimedTranscript)
    (opening : Opening) (message : SmzaRp04ChronologicalAlgebra.OpeningMessage) : Prop :=
  ∀ row coordinate,
    (Interactive.packingVanishing (Finset.univ : Finset (Fin 64)) packingPoint).eval
        (baseOpeningPoints opening.1 coordinate) *
      ((response.nonlinear row).eval (baseOpeningPoints opening.1 coordinate) -
        message.masks.1 coordinate row) =
      ∑ check, matrix row check * paddedNonlinearScalar dsl statement
        (message.witness coordinate) check ∧
    (claimedLinear (candidate dsl certificates statement rows) matrix response row).eval
        (baseOpeningPoints opening.1 coordinate) - message.masks.2 coordinate row =
      ∑ check, matrix row check * paddedLinearScalar dsl statement
        (message.witness coordinate) (baseOpeningPoints opening.1 coordinate) check

theorem scalar_checks_imply_opening_accepts
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (matrix : Matrix (dsl.width statement)) (response : ClaimedTranscript)
    (opening : Opening) (message : SmzaRp04ChronologicalAlgebra.OpeningMessage)
    (columns : reconstructedColumnEvaluations (baseOpeningPoints opening.1)
        message.witness message.masks message.partials =
      (fun coordinate column => (recoveredColumn rows column).eval
        (baseOpeningPoints opening.1 coordinate)))
    (checked : ScalarChecks dsl certificates statement rows matrix response opening message) :
    OpeningAccepts (candidate dsl certificates statement rows) matrix response opening := by
  obtain ⟨witnessReadback, nonlinearReadback, linearReadback⟩ :=
    column_agreement_forces_witness_and_mask_scalars rows
      (baseOpeningPoints opening.1) message.witness message.masks message.partials columns
  have witnessFunctions : ∀ coordinate, message.witness coordinate =
      (fun row => (recoveredWitnessPolynomial rows row).eval
        (baseOpeningPoints opening.1 coordinate)) := by
    intro coordinate
    funext row
    exact witnessReadback coordinate row
  intro row coordinate
  obtain ⟨nonlinear, linear⟩ := checked row coordinate
  rw [witnessFunctions coordinate, nonlinearReadback coordinate row] at nonlinear
  rw [witnessFunctions coordinate, linearReadback coordinate row] at linear
  constructor
  · unfold nonlinearDiscrepancy
      V8Smz9AdmissibleRootProbability.smz9ConsistencyDiscrepancy
      PiopEvaluation.consistencyDiscrepancy
    simp only [eval_sub, eval_mul, PiopExtraction.nonlinearBatch,
      Interactive.batch, Candidate.system, eval_finsetSum, eval_C,
      candidate_nonlinear_evaluation, candidate_nonlinear_mask_evaluation]
    exact sub_eq_zero.mpr nonlinear
  · unfold linearDiscrepancy
    simp only [eval_sub, PiopExtraction.linearBatch, Interactive.batch,
      Candidate.system, eval_finsetSum, eval_mul, eval_C,
      candidate_linear_evaluation, candidate_linear_mask_evaluation]
    exact sub_eq_zero.mpr linear

theorem satisfied_supplies_nonlinear_rows
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (satisfied : PiopExtraction.FullySatisfied
      (candidate dsl certificates statement rows).system) :
    ∀ root lane,
      nonlinearScalar dsl statement
        (fun row => (witnessPolynomials (sourceOfRows rows) row).eval (packingPoint lane)) root = 0 := by
  intro root lane
  let check : Fin (dsl.width statement) :=
    ⟨root.val, root.isLt.trans_le (Nat.le_max_left _ _)⟩
  have zero := satisfied.1 check lane (Finset.mem_univ _)
  change ((candidate dsl certificates statement rows).nonlinear check).eval
    (packingPoint lane) = 0 at zero
  have evalZero : (nonlinearPolynomial dsl statement (sourceOfRows rows) root).eval
      (packingPoint lane) = 0 := by
    simpa only [candidate, paddedNonlinear, check, dif_pos root.isLt] using zero
  exact (nonlinear_polynomial_evaluation dsl certificates statement
    (sourceOfRows rows) root (packingPoint lane)).symm.trans evalZero

theorem satisfied_supplies_linear_rows
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (satisfied : PiopExtraction.FullySatisfied
      (candidate dsl certificates statement rows).system) :
    ∀ linearRow : Fin (dsl.linearCount statement),
      (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
        dsl.linearWeights statement linearRow witnessRow lane *
          ((SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)).getD
            (finProdFinEquiv (witnessRow, lane)).val 0 : Goldilocks)) =
        dsl.linearTarget statement linearRow := by
  intro linearRow
  let check : Fin (dsl.width statement) :=
    ⟨linearRow.val, linearRow.isLt.trans_le (Nat.le_max_right _ _)⟩
  have equal := satisfied.2 check
  change packingSum packingPoint
      ((candidate dsl certificates statement rows).linear check) =
    (candidate dsl certificates statement rows).target check at equal
  simp only [candidate, paddedLinear, paddedTarget, check, dif_pos linearRow.isLt] at equal
  unfold linearPolynomial at equal
  rw [source_linear_packing_sum packingPoint packingPoint_injective] at equal
  rw [← equal]
  apply Finset.sum_congr rfl
  intro witnessRow _
  apply Finset.sum_congr rfl
  intro lane _
  have cell := packed_witness_matches_polynomial (sourceOfRows rows) witnessRow lane
  change ((SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)).getD
      (finProdFinEquiv (witnessRow, lane)).val 0 : Goldilocks) =
    (witnessPolynomials (sourceOfRows rows) witnessRow).eval (packingPoint lane) at cell
  exact congrArg
    (fun value : Goldilocks => dsl.linearWeights statement linearRow witnessRow lane * value)
    cell

theorem packed_coordinate_sum (f : Fin 43904 → Goldilocks) :
    (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
      f (finProdFinEquiv (witnessRow, lane))) = ∑ index, f index := by
  calc
    _ = ∑ coordinate : Fin 686 × Fin 64, f (finProdFinEquiv coordinate) :=
      (Fintype.sum_prod_type _).symm
    _ = _ := Equiv.sum_comp
      (finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904) f

/-- A satisfied normalized row is its dense packed-coordinate equation. -/
theorem normalized_row_equation
    (dsl : RelationDsl) (statement : Statement) (witness : List Nat)
    (equalities : ∀ row : Fin (dsl.linearCount statement),
      (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
        dsl.linearWeights statement row witnessRow lane *
          ((witness.getD (finProdFinEquiv (witnessRow, lane)).val 0 : Nat) : Goldilocks)) =
        dsl.linearTarget statement row)
    (row : Fin (dsl.linearCount statement)) :
    (∑ index : Fin 43904, normalizedRowCoefficient dsl statement row index *
      packedFieldValues witness index) = dsl.linearTarget statement row := by
  rw [← packed_coordinate_sum (fun index =>
    normalizedRowCoefficient dsl statement row index * packedFieldValues witness index)]
  simpa only [normalizedRowCoefficient, packedFieldValues,
    Equiv.symm_apply_apply] using equalities row

/-- The semantic implication formerly stored in the CSR certificate follows
from its finite coefficient/target classification by distributive linear
algebra.  No witness is inspected by the certificate. -/
theorem normalized_rows_imply_executable_equation
    (dsl : RelationDsl) (certificate : CsrCertificate dsl)
    (statement : Statement) (witness : List Nat)
    (equalities : ∀ row : Fin (dsl.linearCount statement),
      (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
        dsl.linearWeights statement row witnessRow lane *
          ((witness.getD (finProdFinEquiv (witnessRow, lane)).val 0 : Nat) : Goldilocks)) =
        dsl.linearTarget statement row)
    (attempt : CsrExecutableAttempt) (member : attempt ∈ dsl.components.csrAttempts) :
    csrFieldSum (csrValues dsl statement) witness attempt.terms =
      ((csrValues dsl statement).getD attempt.targetRoot 0 : Goldilocks) := by
  have bounded : ∀ term, term ∈ attempt.terms → term.1 < 43904 := by
    intro term inTerms
    exact ((certificate.attemptCoordinates attempt member).1 term inTerms).1
  rw [← dense_coefficient_dot (csrValues dsl statement) witness attempt.terms bounded]
  change (∑ index : Fin 43904,
    executableCoefficient dsl statement attempt index * packedFieldValues witness index) =
      executableTarget dsl statement attempt
  rcases certificate.retainedOrZeroOrFallback statement attempt member with
    (⟨row, coefficients, target⟩ | ⟨coefficients, target⟩ |
      ⟨_, targetNonzero, row, fallbackCoefficients, fallbackTarget⟩)
  · calc
      _ = ∑ index : Fin 43904,
          normalizedRowCoefficient dsl statement row index *
            packedFieldValues witness index := by
        apply Finset.sum_congr rfl
        intro index _
        rw [coefficients index]
      _ = dsl.linearTarget statement row :=
        normalized_row_equation dsl statement witness equalities row
      _ = executableTarget dsl statement attempt := target.symm
  · calc
      _ = 0 := by
        apply Finset.sum_eq_zero
        intro index _
        rw [coefficients index, zero_mul]
      _ = executableTarget dsl statement attempt := target.symm
  · obtain ⟨zeroRow, zeroCoefficients, zeroTarget⟩ :=
      certificate.zeroSourceRow statement
    have zeroEquation := normalized_row_equation dsl statement witness equalities zeroRow
    have fallbackEquation := normalized_row_equation dsl statement witness equalities row
    have sameLhs :
        (∑ index : Fin 43904, normalizedRowCoefficient dsl statement row index *
          packedFieldValues witness index) =
        ∑ index : Fin 43904, normalizedRowCoefficient dsl statement zeroRow index *
          packedFieldValues witness index := by
      apply Finset.sum_congr rfl
      intro index _
      rw [fallbackCoefficients index, zeroCoefficients index]
    exfalso
    apply targetNonzero
    exact fallbackTarget.symm.trans
      (fallbackEquation.symm.trans (sameLhs.trans (zeroEquation.trans zeroTarget)))
theorem nonlinear_rows_supply_executable_acceptance
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (publicCanonical : CanonicalPublicWords (currentPublicWords statement))
    (zero : ∀ root lane,
      nonlinearScalar dsl statement
        (fun row => (witnessPolynomials (sourceOfRows rows) row).eval (packingPoint lane)) root = 0)
    (lane : Fin 64) :
    dsl.components.nonlinearExecutable.Accepts (currentPublicWords statement)
      (packedWitnessLaneRows
        (SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)) lane.val) := by
  let packed := SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)
  let values : WitnessPackingValues Goldilocks := fun row lane =>
    (witnessPolynomials (sourceOfRows rows) row).eval (packingPoint lane)
  have valuesEq : values = packingValues packed := by
    funext row lane
    exact (packed_witness_matches_polynomial (sourceOfRows rows) row lane).symm
  rw [← source_packing_rows_match_packed_lane
    (packed_witness_canonical (sourceOfRows rows)) lane, ← valuesEq]
  apply field_roots_zero_supplies_source_acceptance
  · exact Nat.le_of_eq publicCanonical.1.symm
  · simp only [sourcePackingRows, List.length_ofFn, le_refl]
  · exact certificates.nonlinear.programCanonical
  · intro root member
    rw [certificates.nonlinear.rootsExact] at member
    obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
    have vanishes := zero index lane
    change fieldAt dsl.components.nonlinearExecutable.expressions
      (publicFieldAtNat statement)
      (V8Smz9EagerSimulator.openedWitnessAtNat (fun row => values row lane))
      (dsl.nonlinearRoot index) = 0 at vanishes
    rw [source_packing_rows_field_values values lane] at vanishes
    exact vanishes

theorem linear_rows_supply_executable_acceptance
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (publicCanonical : CanonicalPublicWords (currentPublicWords statement))
    (equalities : ∀ linearRow : Fin (dsl.linearCount statement),
      (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
        dsl.linearWeights statement linearRow witnessRow lane *
          ((SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)).getD
            (finProdFinEquiv (witnessRow, lane)).val 0 : Goldilocks)) =
        dsl.linearTarget statement linearRow) :
    csrExecutableProgramAccepts dsl.components.csrExpressions
      dsl.components.csrAttempts (currentPublicWords statement)
      (SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)) := by
  let witness := SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)
  obtain ⟨values, evaluated, valuesLength⟩ := canonical_expression_program_resolves
    (currentPublicWords statement) []
    ({ expressions := dsl.components.csrExpressions, roots := [] } : ExpressionProgram)
    false (Nat.le_of_eq publicCanonical.1.symm)
    (by simp) certificates.csr.programCanonical
  have valuesEq : csrValues dsl statement = values := by
    simp only [csrValues, evaluated, Option.getD_some]
  have valuesCanonical := source_go_canonical (currentPublicWords statement) [] [] values
    dsl.components.csrExpressions (by simp) evaluated
  have witnessLength : witness.length = 43904 := by
    exact (packed_witness_canonical (sourceOfRows rows)).1
  refine ⟨values, evaluated, ?_⟩
  intro attempt member
  have coordinates := certificates.csr.attemptCoordinates attempt member
  apply field_csr_equation_supplies_source_acceptance values witness attempt
  · intro term inTerms
    have bounded := coordinates.1 term inTerms
    simpa only [witnessLength, valuesLength] using bounded
  · simpa only [valuesLength] using coordinates.2
  · exact valuesCanonical
  · rw [← valuesEq]
    exact normalized_rows_imply_executable_equation dsl certificates.csr statement
      witness equalities attempt member

/-- Full PIOP satisfaction now yields the actual executable DSL acceptance;
neither of the desired refinement implications is a certificate field. -/
theorem fully_satisfied_accepts_packed
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (rows : RecoveredRows)
    (satisfied : PiopExtraction.FullySatisfied
      (candidate dsl certificates statement rows).system)
    (publicCanonical : CanonicalPublicWords (currentPublicWords statement)) :
    dsl.components.AcceptsPacked (currentPublicWords statement) (packedFromRows rows) := by
  have nonlinearZero := satisfied_supplies_nonlinear_rows
    dsl certificates statement rows satisfied
  have linearEqual := satisfied_supplies_linear_rows
    dsl certificates statement rows satisfied
  have acceptedSource : dsl.components.AcceptsPacked (currentPublicWords statement)
      (SmzaRp04DecodedPolynomialSource.packedWitness (sourceOfRows rows)) := by
    refine ⟨publicCanonical,
      packed_witness_canonical (sourceOfRows rows), ?_, ?_⟩
    · intro lane bound
      exact nonlinear_rows_supply_executable_acceptance dsl certificates statement rows
        publicCanonical nonlinearZero ⟨lane, bound⟩
    · exact linear_rows_supply_executable_acceptance dsl certificates statement rows
        publicCanonical linearEqual
  simpa only [sourceOfRows,
    SmzaRp04ActualProgram.adapted_packed_witness_is_exact_q38] using acceptedSource

/-- The concrete refinement record consumed by accepted extraction.  Public
canonicality is the verifier's admission predicate and is carried explicitly
by `AcceptedChecks`; it is not asserted for every byte-valued statement. -/
def relationRefinement (dsl : RelationDsl) (certificates : GeneratedCertificates dsl) :
    RelationRefinement (relationModel dsl certificates) where
  StatementValid statement := CanonicalPublicWords (currentPublicWords statement)
  AcceptsPacked statement packed :=
    dsl.components.AcceptsPacked (currentPublicWords statement) packed
  ScalarChecks statement rows matrix response opening message :=
    ScalarChecks dsl certificates statement rows matrix response opening message
  openingAcceptsOfReadback statement rows matrix response opening message columns checked :=
    scalar_checks_imply_opening_accepts dsl certificates statement rows matrix response
      opening message columns checked
  fullySatisfiedAccepts statement rows publicCanonical satisfied :=
    fully_satisfied_accepts_packed dsl certificates statement rows satisfied publicCanonical

end
end HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
