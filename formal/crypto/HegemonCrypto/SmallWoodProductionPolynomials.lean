import HegemonCrypto.SmallWoodOracleExtraction
import HegemonCrypto.SmallWoodNativePackedPolynomial
import HegemonCrypto.SmallWoodPiopEvaluation
import HegemonCrypto.SmallWoodProductionDegreeCertificateGenerated

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-!
# Exact production-polynomial semantics

The production prover evaluates the generated nonlinear expression program over the committed
witness polynomials.  This file gives that operation a direct polynomial meaning and decodes the
five nonlinear and five linear masking polynomials from the exact SmallWood PCS row layout.

These definitions are the bridge needed by the third interactive soundness term.  In particular,
the verifier-opening theorem must not use an arbitrary interpolation that merely agrees with the
transaction relation on the 64 packing points.
-/

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Polynomial
open HegemonCrypto.SmallWood.OracleExtraction
open HegemonCrypto.SmallWood.RoundByRound
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

noncomputable section

/-! ## Generated expression program over polynomials -/

/-- Goldilocks evaluation of one generated expression tree. -/
def treeGoldilocksEval
    (publicValues : List Nat)
    (witnessValue : Nat -> Goldilocks) :
    ProductionConstraintExpressionTree -> Goldilocks
  | .constant value => toGoldilocks value
  | .publicValue index => toGoldilocks (publicValueAt publicValues index)
  | .witnessRow index => witnessValue index
  | .slotInverse slot => toGoldilocks (fieldInverse (slotDenominator publicValues slot))
  | .stableSelector bit =>
      toGoldilocks ((stableSelectorSlot publicValues / (2 ^ bit)) % 2)
  | .add left right =>
      treeGoldilocksEval publicValues witnessValue left +
        treeGoldilocksEval publicValues witnessValue right
  | .sub left right =>
      treeGoldilocksEval publicValues witnessValue left -
        treeGoldilocksEval publicValues witnessValue right
  | .mul left right =>
      treeGoldilocksEval publicValues witnessValue left *
        treeGoldilocksEval publicValues witnessValue right
  | .neg value => -treeGoldilocksEval publicValues witnessValue value

/-- Polynomial represented by one generated expression tree. -/
def treePolynomial
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X]) :
    ProductionConstraintExpressionTree -> Goldilocks[X]
  | .constant value => C (toGoldilocks value)
  | .publicValue index => C (toGoldilocks (publicValueAt publicValues index))
  | .witnessRow index => witnessPolynomialAt index
  | .slotInverse slot =>
      C (toGoldilocks (fieldInverse (slotDenominator publicValues slot)))
  | .stableSelector bit =>
      C (toGoldilocks ((stableSelectorSlot publicValues / (2 ^ bit)) % 2))
  | .add left right =>
      treePolynomial publicValues witnessPolynomialAt left +
        treePolynomial publicValues witnessPolynomialAt right
  | .sub left right =>
      treePolynomial publicValues witnessPolynomialAt left -
        treePolynomial publicValues witnessPolynomialAt right
  | .mul left right =>
      treePolynomial publicValues witnessPolynomialAt left *
        treePolynomial publicValues witnessPolynomialAt right
  | .neg value => -treePolynomial publicValues witnessPolynomialAt value

theorem tree_polynomial_eval
    (tree : ProductionConstraintExpressionTree)
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (point : Goldilocks) :
    (treePolynomial publicValues witnessPolynomialAt tree).eval point =
      treeGoldilocksEval publicValues
        (fun row => (witnessPolynomialAt row).eval point) tree := by
  induction tree <;>
    simp [treePolynomial, treeGoldilocksEval, *]

/-- Polynomial operation performed by one generated DAG instruction. -/
def expressionPolynomial
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (values : Array Goldilocks[X]) :
    ProductionConstraintExpression -> Goldilocks[X]
  | .constExpr value => C (toGoldilocks value)
  | .publicExpr index => C (toGoldilocks (publicValueAt publicValues index))
  | .witnessExpr index => witnessPolynomialAt index
  | .slotInverseExpr slot =>
      C (toGoldilocks (fieldInverse (slotDenominator publicValues slot)))
  | .stableSelectorExpr bit =>
      C (toGoldilocks ((stableSelectorSlot publicValues / (2 ^ bit)) % 2))
  | .addExpr left right => values.getD left 0 + values.getD right 0
  | .subExpr left right => values.getD left 0 - values.getD right 0
  | .mulExpr left right => values.getD left 0 * values.getD right 0
  | .negExpr value => -values.getD value 0

def polynomialProgram
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (expressions : List ProductionConstraintExpression) : Array Goldilocks[X] :=
  expressions.foldl
    (fun values expression =>
      values.push
        (expressionPolynomial publicValues witnessPolynomialAt values expression))
    #[]

/-- Goldilocks execution of one generated DAG instruction. -/
def expressionGoldilocks
    (publicValues : List Nat)
    (witnessValueAt : Nat -> Goldilocks)
    (values : Array Goldilocks) :
    ProductionConstraintExpression -> Goldilocks
  | .constExpr value => toGoldilocks value
  | .publicExpr index => toGoldilocks (publicValueAt publicValues index)
  | .witnessExpr index => witnessValueAt index
  | .slotInverseExpr slot =>
      toGoldilocks (fieldInverse (slotDenominator publicValues slot))
  | .stableSelectorExpr bit =>
      toGoldilocks ((stableSelectorSlot publicValues / (2 ^ bit)) % 2)
  | .addExpr left right => values.getD left 0 + values.getD right 0
  | .subExpr left right => values.getD left 0 - values.getD right 0
  | .mulExpr left right => values.getD left 0 * values.getD right 0
  | .negExpr value => -values.getD value 0

def goldilocksProgram
    (publicValues : List Nat)
    (witnessValueAt : Nat -> Goldilocks)
    (expressions : List ProductionConstraintExpression) : Array Goldilocks :=
  expressions.foldl
    (fun values expression =>
      values.push (expressionGoldilocks publicValues witnessValueAt values expression))
    #[]

theorem array_getD_push_lt
    {Value : Type}
    (values : Array Value)
    (pushed fallback : Value)
    (index : Nat)
    (indexBound : index < values.size) :
    (values.push pushed).getD index fallback =
      values.getD index fallback := by
  simp [Array.getD, indexBound, Nat.le_of_lt indexBound,
    Array.getElem_push_lt]

theorem array_getD_push_eq
    {Value : Type}
    (values : Array Value)
    (pushed fallback : Value) :
    (values.push pushed).getD values.size fallback = pushed := by
  simp [Array.getD, Array.getElem_push_eq]

theorem array_getD_push_of_size_lt
    {Value : Type}
    (values : Array Value)
    (pushed fallback : Value)
    (index : Nat)
    (sizeBeforeIndex : values.size < index) :
    (values.push pushed).getD index fallback = fallback := by
  simp [Array.getD]
  omega

/-- Pointwise evaluation invariant between the polynomial and field DAG executions. -/
def ProgramEvaluationInvariant
    (polynomials : Array Goldilocks[X])
    (values : Array Goldilocks)
    (point : Goldilocks) : Prop :=
  polynomials.size = values.size ∧
    ∀ index,
      (polynomials.getD index 0).eval point = values.getD index 0

theorem expression_polynomial_eval
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (polynomials : Array Goldilocks[X])
    (values : Array Goldilocks)
    (point : Goldilocks)
    (invariant : ProgramEvaluationInvariant polynomials values point)
    (expression : ProductionConstraintExpression) :
    (expressionPolynomial publicValues witnessPolynomialAt polynomials expression).eval point =
      expressionGoldilocks publicValues
        (fun row => (witnessPolynomialAt row).eval point) values expression := by
  cases expression with
  | constExpr value =>
      simp [expressionPolynomial, expressionGoldilocks]
  | publicExpr value =>
      simp [expressionPolynomial, expressionGoldilocks]
  | witnessExpr value =>
      simp [expressionPolynomial, expressionGoldilocks]
  | slotInverseExpr value =>
      simp [expressionPolynomial, expressionGoldilocks]
  | stableSelectorExpr value =>
      simp [expressionPolynomial, expressionGoldilocks]
  | addExpr left right =>
      simp only [expressionPolynomial, expressionGoldilocks, Polynomial.eval_add]
      rw [invariant.2 left, invariant.2 right]
  | subExpr left right =>
      simp only [expressionPolynomial, expressionGoldilocks, Polynomial.eval_sub]
      rw [invariant.2 left, invariant.2 right]
  | mulExpr left right =>
      simp only [expressionPolynomial, expressionGoldilocks, Polynomial.eval_mul]
      rw [invariant.2 left, invariant.2 right]
  | negExpr value =>
      simp only [expressionPolynomial, expressionGoldilocks, Polynomial.eval_neg]
      rw [invariant.2 value]

theorem program_evaluation_invariant_from
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (point : Goldilocks)
    (initialPolynomials : Array Goldilocks[X])
    (initialValues : Array Goldilocks)
    (initialInvariant :
      ProgramEvaluationInvariant initialPolynomials initialValues point)
    (expressions : List ProductionConstraintExpression) :
    ProgramEvaluationInvariant
      (expressions.foldl
        (fun polynomials expression =>
          polynomials.push
            (expressionPolynomial publicValues witnessPolynomialAt
              polynomials expression))
        initialPolynomials)
      (expressions.foldl
        (fun values expression =>
          values.push
            (expressionGoldilocks publicValues
              (fun row => (witnessPolynomialAt row).eval point)
              values expression))
        initialValues)
      point := by
  induction expressions generalizing initialPolynomials initialValues with
  | nil =>
      simpa using initialInvariant
  | cons expression remaining induction =>
      simp only [List.foldl_cons]
      apply induction
      constructor
      · simp [initialInvariant.1]
      · intro index
        by_cases oldIndex : index < initialPolynomials.size
        · have oldValueIndex : index < initialValues.size := by
            rw [← initialInvariant.1]
            exact oldIndex
          rw [array_getD_push_lt _ _ _ _ oldIndex,
            array_getD_push_lt _ _ _ _ oldValueIndex]
          exact initialInvariant.2 index
        · by_cases atEnd : index = initialPolynomials.size
          · subst index
            rw [array_getD_push_eq]
            have valueAtEnd :
                (initialValues.push
                    (expressionGoldilocks publicValues
                      (fun row => (witnessPolynomialAt row).eval point)
                      initialValues expression)).getD
                    initialPolynomials.size 0 =
                  expressionGoldilocks publicValues
                    (fun row => (witnessPolynomialAt row).eval point)
                    initialValues expression := by
              rw [initialInvariant.1, array_getD_push_eq]
            rw [valueAtEnd]
            exact expression_polynomial_eval
              publicValues witnessPolynomialAt initialPolynomials initialValues
              point initialInvariant expression
          · have afterPolynomial :
                initialPolynomials.size < index := by omega
            have afterValue :
                initialValues.size < index := by
              rw [← initialInvariant.1]
              exact afterPolynomial
            rw [array_getD_push_of_size_lt _ _ _ _ afterPolynomial,
              array_getD_push_of_size_lt _ _ _ _ afterValue]
            simp

theorem program_evaluation_invariant
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (expressions : List ProductionConstraintExpression)
    (point : Goldilocks) :
    ProgramEvaluationInvariant
      (polynomialProgram publicValues witnessPolynomialAt expressions)
      (goldilocksProgram publicValues
        (fun row => (witnessPolynomialAt row).eval point) expressions)
      point := by
  unfold polynomialProgram goldilocksProgram
  apply program_evaluation_invariant_from
    publicValues witnessPolynomialAt point #[] #[]
  constructor
  · rfl
  · intro index
    simp [Array.getD]

/-- Pointwise refinement between generated natural-representative and Goldilocks executions. -/
def ProgramFieldRefinement
    (fieldValues : Array Goldilocks)
    (naturalValues : Array Nat) : Prop :=
  fieldValues.size = naturalValues.size ∧
    ∀ index,
      fieldValues.getD index 0 =
        toGoldilocks (naturalValues.getD index 0)

theorem expression_goldilocks_refines_nat
    (publicValues witnessRows : List Nat)
    (fieldValues : Array Goldilocks)
    (naturalValues : Array Nat)
    (refinement : ProgramFieldRefinement fieldValues naturalValues)
    (expression : ProductionConstraintExpression) :
    expressionGoldilocks publicValues
        (fun row => toGoldilocks (witnessRows.getD row 0))
        fieldValues expression =
      toGoldilocks
        (expression.eval publicValues witnessRows naturalValues) := by
  cases expression with
  | constExpr value =>
      exact (toGoldilocks_fieldValue value).symm
  | publicExpr index =>
      rfl
  | witnessExpr index =>
      exact (toGoldilocks_fieldValue (witnessRows.getD index 0)).symm
  | slotInverseExpr slot =>
      rfl
  | stableSelectorExpr bit =>
      exact
        (toGoldilocks_fieldValue
          ((stableSelectorSlot publicValues / 2 ^ bit) % 2)).symm
  | addExpr left right =>
      simp only [expressionGoldilocks, ProductionConstraintExpression.eval,
        toGoldilocks_fieldAdd]
      rw [refinement.2 left, refinement.2 right]
  | subExpr left right =>
      simp only [expressionGoldilocks, ProductionConstraintExpression.eval,
        toGoldilocks_fieldSub]
      rw [refinement.2 left, refinement.2 right]
  | mulExpr left right =>
      simp only [expressionGoldilocks, ProductionConstraintExpression.eval,
        toGoldilocks_fieldMul]
      rw [refinement.2 left, refinement.2 right]
  | negExpr value =>
      simp only [expressionGoldilocks, ProductionConstraintExpression.eval,
        toGoldilocks_fieldNeg]
      rw [refinement.2 value]

theorem program_field_refinement_from
    (publicValues witnessRows : List Nat)
    (initialFieldValues : Array Goldilocks)
    (initialNaturalValues : Array Nat)
    (initialRefinement :
      ProgramFieldRefinement initialFieldValues initialNaturalValues)
    (expressions : List ProductionConstraintExpression) :
    ProgramFieldRefinement
      (expressions.foldl
        (fun values expression =>
          values.push
            (expressionGoldilocks publicValues
              (fun row => toGoldilocks (witnessRows.getD row 0))
              values expression))
        initialFieldValues)
      (evalExpressionProgramFrom
        publicValues witnessRows initialNaturalValues expressions) := by
  induction expressions generalizing initialFieldValues initialNaturalValues with
  | nil =>
      simpa [evalExpressionProgramFrom] using initialRefinement
  | cons expression remaining induction =>
      simp only [List.foldl_cons, evalExpressionProgramFrom]
      apply induction
      constructor
      · simp [initialRefinement.1]
      · intro index
        by_cases oldIndex : index < initialFieldValues.size
        · have oldNaturalIndex : index < initialNaturalValues.size := by
            rw [← initialRefinement.1]
            exact oldIndex
          rw [array_getD_push_lt _ _ _ _ oldIndex,
            array_getD_push_lt _ _ _ _ oldNaturalIndex]
          exact initialRefinement.2 index
        · by_cases atEnd : index = initialFieldValues.size
          · subst index
            rw [array_getD_push_eq]
            have naturalAtEnd :
                (initialNaturalValues.push
                    (expression.eval publicValues witnessRows
                      initialNaturalValues)).getD
                    initialFieldValues.size 0 =
                  expression.eval publicValues witnessRows initialNaturalValues := by
              rw [initialRefinement.1, array_getD_push_eq]
            rw [naturalAtEnd]
            exact expression_goldilocks_refines_nat
              publicValues witnessRows initialFieldValues initialNaturalValues
              initialRefinement expression
          · have afterField :
                initialFieldValues.size < index := by omega
            have afterNatural :
                initialNaturalValues.size < index := by
              rw [← initialRefinement.1]
              exact afterField
            rw [array_getD_push_of_size_lt _ _ _ _ afterField,
              array_getD_push_of_size_lt _ _ _ _ afterNatural]
            rfl

theorem program_field_refinement
    (publicValues witnessRows : List Nat)
    (expressions : List ProductionConstraintExpression) :
    ProgramFieldRefinement
      (goldilocksProgram publicValues
        (fun row => toGoldilocks (witnessRows.getD row 0)) expressions)
      (evalExpressionProgram publicValues witnessRows expressions) := by
  unfold goldilocksProgram evalExpressionProgram
  apply program_field_refinement_from publicValues witnessRows #[] #[]
  constructor
  · rfl
  · intro index
    simp [Array.getD, toGoldilocks]

/-- Pointwise degree invariant for the two lock-step generated DAG evaluators. -/
def ProgramDegreeInvariant
    (polynomials : Array Goldilocks[X])
    (degrees : Array Nat) : Prop :=
  polynomials.size = degrees.size ∧
    ∀ index,
      (polynomials.getD index 0).natDegree ≤
        degrees.getD index 0 * witnessPolynomialDegree

theorem invariant_getD
    (polynomials : Array Goldilocks[X])
    (degrees : Array Nat)
    (invariant : ProgramDegreeInvariant polynomials degrees)
    (index : Nat) :
    (polynomials.getD index 0).natDegree ≤
      degrees.getD index 0 * witnessPolynomialDegree := by
  exact invariant.2 index

theorem expression_polynomial_degree_le
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (witnessDegree :
      ∀ row, (witnessPolynomialAt row).natDegree ≤ witnessPolynomialDegree)
    (polynomials : Array Goldilocks[X])
    (degrees : Array Nat)
    (invariant : ProgramDegreeInvariant polynomials degrees)
    (expression : ProductionConstraintExpression) :
    (expressionPolynomial publicValues witnessPolynomialAt polynomials expression).natDegree ≤
      expressionFormalDegree degrees expression * witnessPolynomialDegree := by
  cases expression with
  | constExpr value => simp [expressionPolynomial, expressionFormalDegree]
  | publicExpr index => simp [expressionPolynomial, expressionFormalDegree]
  | witnessExpr index =>
      simpa [expressionPolynomial, expressionFormalDegree] using witnessDegree index
  | slotInverseExpr slot => simp [expressionPolynomial, expressionFormalDegree]
  | stableSelectorExpr bit => simp [expressionPolynomial, expressionFormalDegree]
  | addExpr left right =>
      exact (natDegree_add_le _ _).trans <|
        max_le
          ((invariant_getD polynomials degrees invariant left).trans <|
            Nat.mul_le_mul_right _ (Nat.le_max_left _ _))
          ((invariant_getD polynomials degrees invariant right).trans <|
            Nat.mul_le_mul_right _ (Nat.le_max_right _ _))
  | subExpr left right =>
      exact (natDegree_sub_le _ _).trans <|
        max_le
          ((invariant_getD polynomials degrees invariant left).trans <|
            Nat.mul_le_mul_right _ (Nat.le_max_left _ _))
          ((invariant_getD polynomials degrees invariant right).trans <|
            Nat.mul_le_mul_right _ (Nat.le_max_right _ _))
  | mulExpr left right =>
      calc
        (polynomials.getD left 0 * polynomials.getD right 0).natDegree ≤
            (polynomials.getD left 0).natDegree +
              (polynomials.getD right 0).natDegree :=
          natDegree_mul_le
        _ ≤ degrees.getD left 0 * witnessPolynomialDegree +
              degrees.getD right 0 * witnessPolynomialDegree :=
          Nat.add_le_add
            (invariant_getD polynomials degrees invariant left)
            (invariant_getD polynomials degrees invariant right)
        _ = (degrees.getD left 0 + degrees.getD right 0) *
              witnessPolynomialDegree := by
          rw [Nat.add_mul]
  | negExpr value =>
      exact natDegree_neg_le_of_le
        (invariant_getD polynomials degrees invariant value)

theorem program_degree_invariant_from
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (witnessDegree :
      ∀ row, (witnessPolynomialAt row).natDegree ≤ witnessPolynomialDegree)
    (initialPolynomials : Array Goldilocks[X])
    (initialDegrees : Array Nat)
    (initialInvariant : ProgramDegreeInvariant initialPolynomials initialDegrees)
    (expressions : List ProductionConstraintExpression) :
    ProgramDegreeInvariant
      (expressions.foldl
        (fun values expression =>
          values.push
            (expressionPolynomial publicValues witnessPolynomialAt values expression))
        initialPolynomials)
      (expressions.foldl
        (fun values expression =>
          values.push (expressionFormalDegree values expression))
        initialDegrees) := by
  induction expressions generalizing initialPolynomials initialDegrees with
  | nil =>
      simpa using initialInvariant
  | cons expression remaining induction =>
      simp only [List.foldl_cons]
      apply induction
      constructor
      · simp [initialInvariant.1]
      · intro index
        by_cases oldIndex : index < initialPolynomials.size
        · have oldDegreeIndex : index < initialDegrees.size := by
            rw [← initialInvariant.1]
            exact oldIndex
          rw [array_getD_push_lt _ _ _ _ oldIndex,
            array_getD_push_lt _ _ _ _ oldDegreeIndex]
          exact initialInvariant.2 index
        · by_cases atEnd : index = initialPolynomials.size
          · subst index
            rw [array_getD_push_eq]
            have degreeAtEnd :
                (initialDegrees.push
                    (expressionFormalDegree initialDegrees expression)).getD
                    initialPolynomials.size 0 =
                  expressionFormalDegree initialDegrees expression := by
              rw [initialInvariant.1, array_getD_push_eq]
            rw [degreeAtEnd]
            exact
              expression_polynomial_degree_le
                publicValues witnessPolynomialAt witnessDegree
                initialPolynomials initialDegrees initialInvariant expression
          · have afterPolynomial :
                initialPolynomials.size < index := by omega
            have afterDegree :
                initialDegrees.size < index := by
              rw [← initialInvariant.1]
              exact afterPolynomial
            rw [array_getD_push_of_size_lt _ _ _ _ afterPolynomial,
              array_getD_push_of_size_lt _ _ _ _ afterDegree]
            simp

theorem program_degree_invariant
    (publicValues : List Nat)
    (witnessPolynomialAt : Nat -> Goldilocks[X])
    (witnessDegree :
      ∀ row, (witnessPolynomialAt row).natDegree ≤ witnessPolynomialDegree)
    (expressions : List ProductionConstraintExpression) :
    ProgramDegreeInvariant
      (polynomialProgram publicValues witnessPolynomialAt expressions)
      (formalDegreeProgram expressions) := by
  unfold polynomialProgram formalDegreeProgram
  apply program_degree_invariant_from
    publicValues witnessPolynomialAt witnessDegree #[] #[]
  constructor
  · rfl
  · intro index
    simp [Array.getD]

/-- Executable check that all 890 generated nonlinear roots have algebraic degree at most eight. -/
def productionConstraintFormalDegree (constraint : Nat) : Nat :=
  (formalDegreeProgram productionNonlinearExpressions).getD
    (productionNonlinearConstraintRoots.getD constraint 0) 0

def productionConstraintDegreesBoundedB : Bool :=
  (List.range nonlinearConstraintCount).all fun constraint =>
    decide
      (productionFormalDegreeAt
          (productionNonlinearConstraintRoots.getD constraint 0) ≤
        effectiveConstraintDegree)

/--
Kernel-checked counterpart of the generated nonlinear-root bound.  The refinement layer exposes
the same proposition through native-code evaluation; cryptographic proof roots use this
declaration so their axiom audit remains kernel-only.
-/
theorem production_nonlinear_roots_are_in_expression_program_kernel :
    ∀ constraint, constraint < productionNonlinearConstraintRoots.length →
      productionNonlinearConstraintRoots.getD constraint 0 <
        productionNonlinearExpressions.length := by
  intro constraint constraintBound
  have checked := (List.all_eq_true.mp (show productionNonlinearRootsBoundB = true by
    decide))
    (productionNonlinearConstraintRoots[constraint]'constraintBound)
    (List.getElem_mem constraintBound)
  simpa [List.getD, constraintBound] using of_decide_eq_true checked

theorem production_constraint_degrees_bounded :
    ∀ constraint, constraint < nonlinearConstraintCount ->
      productionConstraintFormalDegree constraint ≤ effectiveConstraintDegree := by
  intro constraint constraintBound
  have checked :
      productionConstraintDegreesBoundedB = true := by
    decide
  have certificateBound := of_decide_eq_true <|
    (List.all_eq_true.mp checked) constraint (List.mem_range.mpr constraintBound)
  have staticConstraintBound :
      constraint < productionNonlinearConstraintRoots.length := by
    rw [production_nonlinear_root_count_is_exact]
    simpa [nonlinearConstraintCount] using constraintBound
  have rootBound :
      productionNonlinearConstraintRoots.getD constraint 0 <
        productionNonlinearExpressions.length :=
    production_nonlinear_roots_are_in_expression_program_kernel
      constraint staticConstraintBound
  unfold productionConstraintFormalDegree
  rw [formalDegreeProgram_getD_eq_of_certificate
    productionFormalDegreeAt productionNonlinearExpressions
    production_formal_degree_certificate_checked
    (productionNonlinearConstraintRoots.getD constraint 0) rootBound]
  exact certificateBound

/-- Witness polynomial selected by a generated row index; malformed indices fail closed to zero. -/
def extractedWitnessPolynomialAt
    (oracle : CommittedOracle)
    (row : Nat) : Goldilocks[X] :=
  if rowBound : row < rowCount then
    witnessPolynomial oracle ⟨row, rowBound⟩
  else
    0

theorem extracted_witness_polynomial_at_degree_le
    (oracle : CommittedOracle)
    (row : Nat) :
    (extractedWitnessPolynomialAt oracle row).natDegree ≤ witnessPolynomialDegree := by
  unfold extractedWitnessPolynomialAt
  split
  · exact witness_polynomial_degree_le oracle _
  · simp

/--
At every active packing point, the recovered row polynomial is exactly the corresponding
row-major cell of the deterministic extracted witness.
-/
theorem extracted_witness_polynomial_at_packing_point
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (row lane : Nat)
    (rowBound : row < statement.lppcRowCount)
    (laneBound : lane < statement.lppcPackingFactor) :
    (extractedWitnessPolynomialAt oracle row).eval (packingNodePoint lane) =
      toGoldilocks
        ((witnessLaneRows statement (extractWitness oracle) lane).getD row 0) := by
  have activeRowBound : row < rowCount := by
    rw [← active.1]
    exact rowBound
  have activeLaneBound : lane < packingFactor := by
    rw [← active.2.1]
    exact laneBound
  let index : Fin (rowCount * packingFactor) :=
    ⟨row * packingFactor + lane, by
      change row < 699 at activeRowBound
      change lane < 64 at activeLaneBound
      change row * 64 + lane < 699 * 64
      omega⟩
  have canonical := extracted_witness_value_canonical oracle index
  have laneRowsBound :
      row < (witnessLaneRows statement (extractWitness oracle) lane).length := by
    simpa [witnessLaneRows] using rowBound
  have laneRowEquation :
      (witnessLaneRows statement (extractWitness oracle) lane).getD row 0 =
        (extractWitness oracle).getD (row * packingFactor + lane) 0 := by
    rw [List.getD_eq_getElem
      (witnessLaneRows statement (extractWitness oracle) lane) 0 laneRowsBound]
    simp only [witnessLaneRows, List.getElem_map, List.getElem_range]
    rw [active.2.1]
  have extractedGetD :
      (extractWitness oracle).getD index.val 0 =
        (extractWitness oracle).get
          (Fin.cast (extract_witness_length oracle).symm index) := by
    exact List.getD_eq_get
      (extractWitness oracle) 0
      (Fin.cast (extract_witness_length oracle).symm index)
  have rowIndex :
      witnessRowIndex index = ⟨row, activeRowBound⟩ := by
    apply Fin.ext
    change (row * 64 + lane) / 64 = row
    change lane < 64 at activeLaneBound
    omega
  have laneIndex :
      witnessLaneIndex index = ⟨lane, activeLaneBound⟩ := by
    apply Fin.ext
    change (row * 64 + lane) % 64 = lane
    change lane < 64 at activeLaneBound
    omega
  rw [laneRowEquation]
  rw [extractedWitnessPolynomialAt, dif_pos activeRowBound]
  change
    (witnessPolynomial oracle ⟨row, activeRowBound⟩).eval
        (packingNodePoint lane) =
      toGoldilocks ((extractWitness oracle).getD (row * 64 + lane) 0)
  change
    (witnessPolynomial oracle ⟨row, activeRowBound⟩).eval
        (packingNodePoint lane) =
      toGoldilocks ((extractWitness oracle).getD index.val 0)
  rw [extractedGetD]
  simpa only [rowIndex, laneIndex, witnessPackingPoint, packingNodePoint] using
    canonical.symm

/--
Canonical row-major lookup for every natural index. Valid indices recover the corresponding
witness cell; malformed indices make both the polynomial and list lookup fail closed to zero.
-/
theorem extracted_witness_polynomial_at_flat_index
    (oracle : CommittedOracle)
    (index : Nat) :
    (extractedWitnessPolynomialAt oracle (index / packingFactor)).eval
        (packingNodePoint (index % packingFactor)) =
      toGoldilocks ((extractWitness oracle).getD index 0) := by
  by_cases indexBound : index < rowCount * packingFactor
  · let finiteIndex : Fin (rowCount * packingFactor) := ⟨index, indexBound⟩
    have rowBound : index / packingFactor < rowCount := by
      change index / 64 < 699
      change index < 699 * 64 at indexBound
      omega
    have rowIndex :
        witnessRowIndex finiteIndex = ⟨index / packingFactor, rowBound⟩ := by
      apply Fin.ext
      rfl
    have laneIndex :
        witnessLaneIndex finiteIndex =
          ⟨index % packingFactor, Nat.mod_lt _ (by decide)⟩ := by
      apply Fin.ext
      rfl
    have extractedGetD :
        (extractWitness oracle).getD index 0 =
          (extractWitness oracle).get
            (Fin.cast (extract_witness_length oracle).symm finiteIndex) := by
      exact List.getD_eq_get
        (extractWitness oracle) 0
        (Fin.cast (extract_witness_length oracle).symm finiteIndex)
    rw [extractedWitnessPolynomialAt, dif_pos rowBound, extractedGetD]
    simpa only [rowIndex, laneIndex, witnessPackingPoint, packingNodePoint] using
      (extracted_witness_value_canonical oracle finiteIndex).symm
  · have rowOutside : ¬index / packingFactor < rowCount := by
      intro rowBound
      have laneBound : index % packingFactor < packingFactor :=
        Nat.mod_lt _ (by decide)
      change index / 64 < 699 at rowBound
      change index % 64 < 64 at laneBound
      change ¬index < 699 * 64 at indexBound
      omega
    have outsideList : (extractWitness oracle).length ≤ index := by
      rw [extract_witness_length]
      exact Nat.le_of_not_gt indexBound
    rw [extractedWitnessPolynomialAt, dif_neg rowOutside,
      List.getD_eq_default (extractWitness oracle) 0 outsideList]
    simp [toGoldilocks]

/-- Exact nonlinear polynomial evaluated by Rust for one generated production constraint. -/
def productionNonlinearPolynomial
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat) : Goldilocks[X] :=
  (polynomialProgram
      statement.publicValues
      (extractedWitnessPolynomialAt oracle)
      productionNonlinearExpressions).getD
    (productionNonlinearConstraintRoots.getD constraint 0) 0

theorem production_nonlinear_polynomial_degree_le
    (statement : Statement)
    (oracle : CommittedOracle)
    (constraint : Nat)
    (constraintBound : constraint < nonlinearConstraintCount) :
    (productionNonlinearPolynomial statement oracle constraint).natDegree ≤
      effectiveConstraintDegree * witnessPolynomialDegree := by
  have invariant :=
    program_degree_invariant
      statement.publicValues
      (extractedWitnessPolynomialAt oracle)
      (extracted_witness_polynomial_at_degree_le oracle)
      productionNonlinearExpressions
  exact
    (invariant_getD _ _ invariant
      (productionNonlinearConstraintRoots.getD constraint 0)).trans
      (Nat.mul_le_mul_right witnessPolynomialDegree <|
        production_constraint_degrees_bounded constraint constraintBound)

/--
The exact generated polynomial agrees with the production relation evaluator at every active
packing point.  This is the off-domain Rust polynomial specialized back to the 64 witness lanes,
not a replacement interpolation.
-/
theorem production_nonlinear_polynomial_at_packing_point
    (statement : Statement)
    (oracle : CommittedOracle)
    (active : ActiveStatement statement)
    (constraint lane : Nat)
    (constraintBound : constraint < statement.nonlinearConstraintCount)
    (laneBound : lane < statement.lppcPackingFactor) :
    (productionNonlinearPolynomial statement oracle constraint).eval
        (packingNodePoint lane) =
      toGoldilocks
        (nonlinearConstraintValue statement (extractWitness oracle) lane constraint) := by
  have witnessFunction :
      (fun row =>
        (extractedWitnessPolynomialAt oracle row).eval (packingNodePoint lane)) =
      (fun row =>
        toGoldilocks
          ((witnessLaneRows statement (extractWitness oracle) lane).getD row 0)) := by
    funext row
    by_cases rowBound : row < statement.lppcRowCount
    · exact extracted_witness_polynomial_at_packing_point
        statement oracle active row lane rowBound laneBound
    · have activeRowOutside : ¬row < rowCount := by
        rw [← active.1]
        exact rowBound
      rw [extractedWitnessPolynomialAt, dif_neg activeRowOutside]
      have outsideLaneRows :
          (witnessLaneRows statement (extractWitness oracle) lane).length ≤ row := by
        simpa [witnessLaneRows] using Nat.le_of_not_gt rowBound
      rw [List.getD_eq_default
        (witnessLaneRows statement (extractWitness oracle) lane) 0 outsideLaneRows]
      simp [toGoldilocks]
  let root := productionNonlinearConstraintRoots.getD constraint 0
  have polynomialEvaluation :=
    (program_evaluation_invariant
      statement.publicValues
      (extractedWitnessPolynomialAt oracle)
      productionNonlinearExpressions
      (packingNodePoint lane)).2 root
  rw [witnessFunction] at polynomialEvaluation
  have fieldRefinement :=
    (program_field_refinement
      statement.publicValues
      (witnessLaneRows statement (extractWitness oracle) lane)
      productionNonlinearExpressions).2 root
  have staticProgram :=
    production_constraint_map_bound_uses_static_nonlinear_program
      active.2.2.2.2.2
  have staticConstraintBound :
      constraint < productionNonlinearConstraintRoots.length := by
    rw [production_nonlinear_root_count_is_exact]
    have countEquation :
        statement.nonlinearConstraintCount = 890 := by
      simpa [nonlinearConstraintCount] using active.2.2.2.1
    omega
  have rootBound :
      root < productionNonlinearExpressions.length := by
    exact production_nonlinear_roots_are_in_expression_program_kernel
      constraint staticConstraintBound
  have evaluatedRootBound :
      root <
        (evalExpressionProgram
          statement.publicValues
          (witnessLaneRows statement (extractWitness oracle) lane)
          productionNonlinearExpressions).size := by
    rw [eval_expression_program_size]
    exact rootBound
  have fallbackIrrelevant :
      (evalExpressionProgram
        statement.publicValues
        (witnessLaneRows statement (extractWitness oracle) lane)
        productionNonlinearExpressions).getD root 1 =
      (evalExpressionProgram
        statement.publicValues
        (witnessLaneRows statement (extractWitness oracle) lane)
        productionNonlinearExpressions).getD root 0 := by
    simp [Array.getD, evaluatedRootBound]
  calc
    (productionNonlinearPolynomial statement oracle constraint).eval
        (packingNodePoint lane) =
        (goldilocksProgram statement.publicValues
          (fun row =>
            toGoldilocks
              ((witnessLaneRows statement (extractWitness oracle) lane).getD row 0))
          productionNonlinearExpressions).getD root 0 := by
      exact polynomialEvaluation
    _ = toGoldilocks
        ((evalExpressionProgram
          statement.publicValues
          (witnessLaneRows statement (extractWitness oracle) lane)
          productionNonlinearExpressions).getD root 0) :=
      fieldRefinement
    _ = toGoldilocks
        (nonlinearConstraintValue statement (extractWitness oracle) lane constraint) := by
      unfold nonlinearConstraintValue
      rw [staticProgram.1, staticProgram.2, fallbackIrrelevant]

/-! ## Verifier-exact packed PCS masks -/

abbrev nonlinearMaskOffset :=
  HegemonCrypto.SmallWood.NativePackedPolynomial.nonlinearMaskOffset

abbrev linearMaskOffset :=
  HegemonCrypto.SmallWood.NativePackedPolynomial.linearMaskOffset

/--
The nonlinear mask as evaluated from every committed cell in its eight-column PCS span.  Unlike
the retired authoring decoder, this definition makes no assumption that padding cells are zero.
-/
abbrev nonlinearMaskPolynomial :=
  HegemonCrypto.SmallWood.NativePackedPolynomial.nonlinearMaskPolynomial

/-- The sparse-linear mask as evaluated from every committed cell in its two-column PCS span. -/
abbrev linearMaskPolynomial :=
  HegemonCrypto.SmallWood.NativePackedPolynomial.linearMaskPolynomial

theorem nonlinear_mask_polynomial_degree_le
    (oracle : CommittedOracle)
    (repetition : Fin rho) :
    (nonlinearMaskPolynomial oracle repetition).natDegree ≤
      nonlinearMaskPolynomialDegree :=
  HegemonCrypto.SmallWood.NativePackedPolynomial.nonlinear_mask_polynomial_degree_le
    oracle repetition

theorem linear_mask_polynomial_degree_le
    (oracle : CommittedOracle)
    (repetition : Fin rho) :
    (linearMaskPolynomial oracle repetition).natDegree ≤
      linearMaskPolynomialDegree :=
  HegemonCrypto.SmallWood.NativePackedPolynomial.linear_mask_polynomial_degree_le
    oracle repetition

end

end HegemonCrypto.SmallWood.ProductionPolynomials
