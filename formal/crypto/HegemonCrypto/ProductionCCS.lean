import HegemonCrypto.Goldilocks
import HegemonCrypto.QuadraticProgram
import HegemonCrypto.SmallWoodRelation

/-!
# Production SmallWood to quadratic CCS

This module gives the generated production arithmetic program an explicit quadratic layout. It
does not encode map canonicality as secret algebra: callers must establish
`ProductionConstraintMapBound` before using extraction soundness.
-/

namespace HegemonCrypto.SmallWood.ProductionCCS

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open HegemonCrypto.QuadraticProgram

def witnessCellCount (statement : Statement) : Nat :=
  statement.lppcRowCount * statement.lppcPackingFactor

def expressionCellCount (statement : Statement) : Nat :=
  statement.lppcPackingFactor * statement.nonlinearExpressionCount

def programVariableCount (statement : Statement) : Nat :=
  witnessCellCount statement + expressionCellCount statement

def expressionRowCount (statement : Statement) : Nat :=
  expressionCellCount statement

def rootRowCount (statement : Statement) : Nat :=
  statement.lppcPackingFactor * statement.nonlinearConstraintCount

def programRowCount (statement : Statement) : Nat :=
  statement.linearConstraintCount + expressionRowCount statement + rootRowCount statement

def expressionCellIndex (statement : Statement) (lane expression : Nat) : Nat :=
  witnessCellCount statement + lane * statement.nonlinearExpressionCount + expression

private def zeroForm (statement : Statement) :
    AffineForm Goldilocks (programVariableCount statement) where
  constant := 0
  coefficient := fun _ => 0

private def variableForm
    (statement : Statement)
    (index : Nat)
    (scale : Goldilocks := 1) :
    AffineForm Goldilocks (programVariableCount statement) where
  constant := 0
  coefficient := fun cell => if cell.val = index then scale else 0

private def affineCombination
    (statement : Statement)
    (constant : Goldilocks)
    (terms : List (Nat × Goldilocks)) :
    AffineForm Goldilocks (programVariableCount statement) where
  constant := constant
  coefficient := fun cell =>
    (terms.map fun term => if cell.val = term.1 then term.2 else 0).sum

private def assignmentAt
    {variableCount : Nat}
    (assignment : Fin variableCount → Goldilocks)
    (index : Nat) : Goldilocks :=
  if h : index < variableCount then assignment ⟨index, h⟩ else 0

private theorem selector_sum
    {variableCount : Nat}
    (assignment : Fin variableCount → Goldilocks)
    (index : Nat)
    (scale : Goldilocks) :
    (∑ cell : Fin variableCount,
      (if cell.val = index then scale else 0) * assignment cell) =
        scale * assignmentAt assignment index := by
  classical
  by_cases h : index < variableCount
  · let target : Fin variableCount := ⟨index, h⟩
    rw [Fintype.sum_eq_single target]
    · simp [assignmentAt, h, target]
    · intro cell hne
      simp only [ite_mul, zero_mul]
      split
      · rename_i heq
        exfalso
        apply hne
        exact Fin.ext heq
      · rfl
  · have hne : ∀ cell : Fin variableCount, cell.val ≠ index := by
      intro cell heq
      exact h (heq ▸ cell.isLt)
    simp [assignmentAt, h, hne]

private theorem sparseCoefficient_sum
    {variableCount : Nat}
    (terms : List (Nat × Goldilocks))
    (assignment : Fin variableCount → Goldilocks) :
    (∑ cell : Fin variableCount,
      (terms.map fun term => if cell.val = term.1 then term.2 else 0).sum *
        assignment cell) =
      (terms.map fun term => term.2 * assignmentAt assignment term.1).sum := by
  classical
  induction terms with
  | nil => simp
  | cons term rest inductionHypothesis =>
      simp only [List.map_cons, List.sum_cons, add_mul, Finset.sum_add_distrib]
      rw [selector_sum, inductionHypothesis]

private theorem affineCombination_eval
    (statement : Statement)
    (constant : Goldilocks)
    (terms : List (Nat × Goldilocks))
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (affineCombination statement constant terms).eval assignment =
      constant +
        (terms.map fun term => term.2 * assignmentAt assignment term.1).sum := by
  simp [AffineForm.eval, affineCombination, sparseCoefficient_sum]

private theorem zeroForm_eval
    (statement : Statement)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (zeroForm statement).eval assignment = 0 := by
  simp [zeroForm, AffineForm.eval]

private theorem variableForm_eval
    (statement : Statement)
    (index : Nat)
    (scale : Goldilocks)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (variableForm statement index scale).eval assignment =
      scale * assignmentAt assignment index := by
  rw [variableForm, AffineForm.eval]
  simp only [zero_add]
  exact selector_sum assignment index scale

private def linearConstraintTerms
    (statement : Statement)
    (constraint : Nat) : List (Nat × Goldilocks) :=
  let start := statement.linearTermOffsets.getD constraint 0
  let stop := statement.linearTermOffsets.getD (constraint + 1) start
  (List.range (stop - start)).map fun relativeTerm =>
    let term := start + relativeTerm
    let index := statement.linearTermIndices.getD term 0
    ( index,
      if index < witnessCellCount statement then
        toGoldilocks (statement.linearTermCoefficients.getD term 0)
      else 0 )

private def linearEquation
    (statement : Statement)
    (constraint : Nat) :
    Equation Goldilocks (programVariableCount statement) where
  left := zeroForm statement
  right := zeroForm statement
  linear := affineCombination statement
    (-toGoldilocks (statement.linearTargets.getD constraint 0))
    (linearConstraintTerms statement constraint)

private def constantEquation
    (statement : Statement)
    (target : Nat)
    (value : Goldilocks) :
    Equation Goldilocks (programVariableCount statement) where
  left := zeroForm statement
  right := zeroForm statement
  linear := affineCombination statement (-value) [(target, 1)]

private def addEquation
    (statement : Statement)
    (target left right : Nat) :
    Equation Goldilocks (programVariableCount statement) where
  left := zeroForm statement
  right := zeroForm statement
  linear := affineCombination statement 0 [(target, 1), (left, -1), (right, -1)]

private def subEquation
    (statement : Statement)
    (target left right : Nat) :
    Equation Goldilocks (programVariableCount statement) where
  left := zeroForm statement
  right := zeroForm statement
  linear := affineCombination statement 0 [(target, 1), (left, -1), (right, 1)]

private def mulEquation
    (statement : Statement)
    (target left right : Nat) :
    Equation Goldilocks (programVariableCount statement) where
  left := variableForm statement left
  right := variableForm statement right
  linear := variableForm statement target (-1)

private def negEquation
    (statement : Statement)
    (target value : Nat) :
    Equation Goldilocks (programVariableCount statement) where
  left := zeroForm statement
  right := zeroForm statement
  linear := affineCombination statement 0 [(target, 1), (value, 1)]

private def copyEquation
    (statement : Statement)
    (target source : Nat) :
    Equation Goldilocks (programVariableCount statement) where
  left := zeroForm statement
  right := zeroForm statement
  linear := affineCombination statement 0 [(target, 1), (source, -1)]

private theorem constantEquation_satisfied_iff
    (statement : Statement)
    (target : Nat)
    (value : Goldilocks)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (constantEquation statement target value).Satisfied assignment ↔
      assignmentAt assignment target = value := by
  simp only [Equation.Satisfied, constantEquation, zeroForm_eval,
    affineCombination_eval, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    one_mul, add_zero, zero_mul, zero_add]
  rw [show -value + assignmentAt assignment target =
      assignmentAt assignment target - value by ring]
  exact sub_eq_zero

private theorem addEquation_satisfied_iff
    (statement : Statement)
    (target left right : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (addEquation statement target left right).Satisfied assignment ↔
      assignmentAt assignment target =
        assignmentAt assignment left + assignmentAt assignment right := by
  simp only [Equation.Satisfied, addEquation, zeroForm_eval, affineCombination_eval,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one_mul, neg_mul,
    add_zero, zero_mul, zero_add]
  constructor
  · intro satisfied
    apply sub_eq_zero.mp
    rw [show assignmentAt assignment target -
          (assignmentAt assignment left + assignmentAt assignment right) =
        assignmentAt assignment target +
          (-assignmentAt assignment left + -assignmentAt assignment right) by ring]
    exact satisfied
  · intro equation
    rw [equation]
    ring

private theorem subEquation_satisfied_iff
    (statement : Statement)
    (target left right : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (subEquation statement target left right).Satisfied assignment ↔
      assignmentAt assignment target =
        assignmentAt assignment left - assignmentAt assignment right := by
  simp only [Equation.Satisfied, subEquation, zeroForm_eval, affineCombination_eval,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one_mul, neg_mul,
    add_zero, zero_mul, zero_add]
  constructor
  · intro satisfied
    apply sub_eq_zero.mp
    rw [show assignmentAt assignment target -
          (assignmentAt assignment left - assignmentAt assignment right) =
        assignmentAt assignment target +
          (-assignmentAt assignment left + assignmentAt assignment right) by ring]
    exact satisfied
  · intro equation
    rw [equation]
    ring

private theorem mulEquation_satisfied_iff
    (statement : Statement)
    (target left right : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (mulEquation statement target left right).Satisfied assignment ↔
      assignmentAt assignment target =
        assignmentAt assignment left * assignmentAt assignment right := by
  simp only [Equation.Satisfied, mulEquation, variableForm_eval]
  constructor
  · intro satisfied
    symm
    apply sub_eq_zero.mp
    rw [show assignmentAt assignment left * assignmentAt assignment right -
          assignmentAt assignment target =
        1 * assignmentAt assignment left * (1 * assignmentAt assignment right) +
          (-1) * assignmentAt assignment target by ring]
    exact satisfied
  · intro equation
    rw [equation]
    ring

private theorem negEquation_satisfied_iff
    (statement : Statement)
    (target value : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (negEquation statement target value).Satisfied assignment ↔
      assignmentAt assignment target = -assignmentAt assignment value := by
  simp only [Equation.Satisfied, negEquation, zeroForm_eval, affineCombination_eval,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one_mul, add_zero,
    zero_mul, zero_add]
  rw [show assignmentAt assignment target + assignmentAt assignment value =
      assignmentAt assignment target - -assignmentAt assignment value by ring]
  exact sub_eq_zero

private theorem copyEquation_satisfied_iff
    (statement : Statement)
    (target source : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (copyEquation statement target source).Satisfied assignment ↔
      assignmentAt assignment target = assignmentAt assignment source := by
  simp only [Equation.Satisfied, copyEquation, zeroForm_eval, affineCombination_eval,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one_mul, neg_mul,
    add_zero, zero_mul, zero_add]
  rw [show assignmentAt assignment target + -assignmentAt assignment source =
      assignmentAt assignment target - assignmentAt assignment source by ring]
  exact sub_eq_zero

private def expressionEquation
    (statement : Statement)
    (lane expressionIndex : Nat) :
    Equation Goldilocks (programVariableCount statement) :=
  let target := expressionCellIndex statement lane expressionIndex
  match statement.nonlinearExpressions.getD expressionIndex (.constExpr 1) with
  | .constExpr value =>
      constantEquation statement target (toGoldilocks value)
  | .publicExpr index =>
      constantEquation statement target
        (toGoldilocks (publicValueAt statement.publicValues index))
  | .witnessExpr index =>
      copyEquation statement target (index * statement.lppcPackingFactor + lane)
  | .slotInverseExpr slot =>
      constantEquation statement target
        (toGoldilocks (fieldInverse (slotDenominator statement.publicValues slot)))
  | .stableSelectorExpr bit =>
      constantEquation statement target
        (toGoldilocks ((stableSelectorSlot statement.publicValues / (2 ^ bit)) % 2))
  | .addExpr left right =>
      addEquation statement target
        (expressionCellIndex statement lane left)
        (expressionCellIndex statement lane right)
  | .subExpr left right =>
      subEquation statement target
        (expressionCellIndex statement lane left)
        (expressionCellIndex statement lane right)
  | .mulExpr left right =>
      mulEquation statement target
        (expressionCellIndex statement lane left)
        (expressionCellIndex statement lane right)
  | .negExpr value =>
      negEquation statement target (expressionCellIndex statement lane value)

private def expressionAssignmentValue
    (statement : Statement)
    (lane expressionIndex : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) : Goldilocks :=
  match statement.nonlinearExpressions.getD expressionIndex (.constExpr 1) with
  | .constExpr value => toGoldilocks value
  | .publicExpr index => toGoldilocks (publicValueAt statement.publicValues index)
  | .witnessExpr index =>
      assignmentAt assignment (index * statement.lppcPackingFactor + lane)
  | .slotInverseExpr slot =>
      toGoldilocks (fieldInverse (slotDenominator statement.publicValues slot))
  | .stableSelectorExpr bit =>
      toGoldilocks ((stableSelectorSlot statement.publicValues / (2 ^ bit)) % 2)
  | .addExpr left right =>
      assignmentAt assignment (expressionCellIndex statement lane left) +
        assignmentAt assignment (expressionCellIndex statement lane right)
  | .subExpr left right =>
      assignmentAt assignment (expressionCellIndex statement lane left) -
        assignmentAt assignment (expressionCellIndex statement lane right)
  | .mulExpr left right =>
      assignmentAt assignment (expressionCellIndex statement lane left) *
        assignmentAt assignment (expressionCellIndex statement lane right)
  | .negExpr value =>
      -assignmentAt assignment (expressionCellIndex statement lane value)

private theorem expressionEquation_satisfied_iff
    (statement : Statement)
    (lane expression : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (expressionEquation statement lane expression).Satisfied assignment ↔
      assignmentAt assignment (expressionCellIndex statement lane expression) =
        expressionAssignmentValue statement lane expression assignment := by
  unfold expressionEquation expressionAssignmentValue
  cases selected : statement.nonlinearExpressions.getD expression (.constExpr 1) with
  | constExpr value =>
      exact constantEquation_satisfied_iff statement _ _ assignment
  | publicExpr index =>
      exact constantEquation_satisfied_iff statement _ _ assignment
  | witnessExpr index =>
      exact copyEquation_satisfied_iff statement _ _ assignment
  | slotInverseExpr slot =>
      exact constantEquation_satisfied_iff statement _ _ assignment
  | stableSelectorExpr bit =>
      exact constantEquation_satisfied_iff statement _ _ assignment
  | addExpr left right =>
      exact addEquation_satisfied_iff statement _ _ _ assignment
  | subExpr left right =>
      exact subEquation_satisfied_iff statement _ _ _ assignment
  | mulExpr left right =>
      exact mulEquation_satisfied_iff statement _ _ _ assignment
  | negExpr value =>
      exact negEquation_satisfied_iff statement _ _ assignment

private def rootEquation
    (statement : Statement)
    (lane constraint : Nat) :
    Equation Goldilocks (programVariableCount statement) :=
  let root := statement.nonlinearConstraintRoots.getD constraint 0
  constantEquation statement (expressionCellIndex statement lane root) 0

private def equationAt
    (statement : Statement)
    (row : Nat) : Equation Goldilocks (programVariableCount statement) :=
  if row < statement.linearConstraintCount then
    linearEquation statement row
  else
    let nonlinearRow := row - statement.linearConstraintCount
    if nonlinearRow < expressionRowCount statement then
      let expressionCount := statement.nonlinearExpressionCount
      let lane := nonlinearRow / expressionCount
      let expression := nonlinearRow % expressionCount
      expressionEquation statement lane expression
    else
      let rootRow := nonlinearRow - expressionRowCount statement
      let constraintCount := statement.nonlinearConstraintCount
      let lane := rootRow / constraintCount
      let constraint := rootRow % constraintCount
      rootEquation statement lane constraint

/-- The exact linear-size quadratic program generated from one public production statement. -/
def program (statement : Statement) : Program Goldilocks where
  variableCount := programVariableCount statement
  rowCount := programRowCount statement
  equation := fun row => equationAt statement row.val

private def expressionValue
    (statement : Statement)
    (witness : Witness)
    (lane expression : Nat) : Nat :=
  let values := evalExpressionProgram statement.publicValues
    (witnessLaneRows statement witness lane) statement.nonlinearExpressions
  values.getD expression 0

/-- Honest assignment containing raw witness cells followed by every expression-DAG value. -/
def encodeProgram
    (statement : Statement)
    (witness : Witness) : Fin (program statement).variableCount → Goldilocks :=
  fun cell =>
    if cell.val < witnessCellCount statement then
      toGoldilocks (witness.getD cell.val 0)
    else
      let offset := cell.val - witnessCellCount statement
      let expressionCount := statement.nonlinearExpressionCount
      let lane := offset / expressionCount
      let expression := offset % expressionCount
      toGoldilocks (expressionValue statement witness lane expression)

private theorem assignmentAt_encodeProgram_witness
    (statement : Statement)
    (witness : Witness)
    (index : Nat)
    (indexBound : index < witnessCellCount statement) :
    assignmentAt (encodeProgram statement witness) index =
      toGoldilocks (witness.getD index 0) := by
  have variableBound : index < programVariableCount statement :=
    indexBound.trans_le (Nat.le_add_right _ _)
  simp [assignmentAt, encodeProgram, program, variableBound, indexBound]

private theorem expressionCellIndex_lt
    (statement : Statement)
    (lane expression : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (expressionBound : expression < statement.nonlinearExpressionCount) :
    expressionCellIndex statement lane expression < programVariableCount statement := by
  have expressionPositive : 0 < statement.nonlinearExpressionCount :=
    Nat.zero_lt_of_lt expressionBound
  have laneSuccessorBound : lane + 1 ≤ statement.lppcPackingFactor :=
    Nat.succ_le_iff.mpr laneBound
  have offsetBound :
      lane * statement.nonlinearExpressionCount + expression <
        statement.lppcPackingFactor * statement.nonlinearExpressionCount := by
    calc
      lane * statement.nonlinearExpressionCount + expression <
          lane * statement.nonlinearExpressionCount +
            statement.nonlinearExpressionCount :=
        Nat.add_lt_add_left expressionBound _
      _ = (lane + 1) * statement.nonlinearExpressionCount := by
        simp [Nat.add_mul, Nat.add_comm]
      _ ≤ statement.lppcPackingFactor * statement.nonlinearExpressionCount :=
        Nat.mul_le_mul_right statement.nonlinearExpressionCount laneSuccessorBound
  change
    witnessCellCount statement +
        lane * statement.nonlinearExpressionCount + expression <
      witnessCellCount statement +
        statement.lppcPackingFactor * statement.nonlinearExpressionCount
  omega

private theorem assignmentAt_encodeProgram_expression
    (statement : Statement)
    (witness : Witness)
    (lane expression : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (expressionBound : expression < statement.nonlinearExpressionCount) :
    assignmentAt (encodeProgram statement witness)
        (expressionCellIndex statement lane expression) =
      toGoldilocks (expressionValue statement witness lane expression) := by
  have expressionPositive : 0 < statement.nonlinearExpressionCount :=
    Nat.zero_lt_of_lt expressionBound
  have cellBound := expressionCellIndex_lt statement lane expression laneBound expressionBound
  have programCellBound :
      expressionCellIndex statement lane expression < (program statement).variableCount := by
    simpa [program] using cellBound
  have notWitness :
      ¬ expressionCellIndex statement lane expression < witnessCellCount statement := by
    apply Nat.not_lt.mpr
    simp only [expressionCellIndex]
    omega
  unfold assignmentAt
  rw [dif_pos programCellBound]
  change
    (if expressionCellIndex statement lane expression < witnessCellCount statement then
      toGoldilocks (witness.getD (expressionCellIndex statement lane expression) 0)
    else
      let offset := expressionCellIndex statement lane expression - witnessCellCount statement
      let expressionCount := statement.nonlinearExpressionCount
      let selectedLane := offset / expressionCount
      let selectedExpression := offset % expressionCount
      toGoldilocks
        (expressionValue statement witness selectedLane selectedExpression)) = _
  rw [if_neg notWitness]
  simp only [expressionCellIndex]
  rw [show
      witnessCellCount statement + lane * statement.nonlinearExpressionCount + expression =
        witnessCellCount statement +
          (lane * statement.nonlinearExpressionCount + expression) by omega]
  rw [Nat.add_sub_cancel_left]
  rw [show
      (lane * statement.nonlinearExpressionCount + expression) /
          statement.nonlinearExpressionCount = lane by
        rw [Nat.mul_comm]
        simp [Nat.mul_add_div expressionPositive, Nat.div_eq_of_lt expressionBound]]
  rw [show
      (lane * statement.nonlinearExpressionCount + expression) %
          statement.nonlinearExpressionCount = expression by
        exact Nat.mul_add_mod_of_lt expressionBound]

private theorem toGoldilocks_foldl_fieldAdd
    (values : List Nat)
    (initial : Nat) :
    toGoldilocks (values.foldl fieldAdd initial) =
      toGoldilocks initial + (values.map toGoldilocks).sum := by
  induction values generalizing initial with
  | nil => simp
  | cons value values inductionHypothesis =>
      simp only [List.foldl_cons, List.map_cons, List.sum_cons]
      rw [inductionHypothesis, toGoldilocks_fieldAdd]
      ring

private theorem fieldValue_foldl_fieldAdd
    (values : List Nat)
    (initial : Nat)
    (initialCanonical : fieldValue initial = initial) :
    fieldValue (values.foldl fieldAdd initial) = values.foldl fieldAdd initial := by
  induction values generalizing initial with
  | nil => exact initialCanonical
  | cons value values inductionHypothesis =>
      simp only [List.foldl_cons]
      apply inductionHypothesis
      simp [fieldValue, fieldAdd]

private theorem fieldAdd_canonical (left right : Nat) :
    fieldValue (fieldAdd left right) = fieldAdd left right := by
  simp [fieldValue, fieldAdd]

private theorem fieldSub_canonical (left right : Nat) :
    fieldValue (fieldSub left right) = fieldSub left right := by
  simp [fieldValue, fieldSub]

private theorem fieldMul_canonical (left right : Nat) :
    fieldValue (fieldMul left right) = fieldMul left right := by
  simp [fieldValue, fieldMul]

private theorem fieldPow_canonical (base exponent : Nat) :
    fieldValue (fieldPow base exponent) = fieldPow base exponent := by
  rw [fieldPow]
  split
  · norm_num [fieldValue, goldilocksModulus]
  · dsimp only
    split <;> apply fieldMul_canonical

private theorem fieldInverse_canonical (value : Nat) :
    fieldValue (fieldInverse value) = fieldInverse value := by
  unfold fieldInverse
  split
  · simp [fieldValue]
  · exact fieldPow_canonical _ _

private theorem fieldNeg_canonical (value : Nat) :
    fieldValue (fieldNeg value) = fieldNeg value := by
  exact fieldSub_canonical _ _

private theorem expressionEval_canonical
    (expression : ProductionConstraintExpression)
    (publicValues witnessRows : List Nat)
    (values : Array Nat) :
    fieldValue (expression.eval publicValues witnessRows values) =
      expression.eval publicValues witnessRows values := by
  cases expression with
  | constExpr value => simp [ProductionConstraintExpression.eval, fieldValue]
  | publicExpr index => simp [ProductionConstraintExpression.eval, publicValueAt, fieldValue]
  | witnessExpr index => simp [ProductionConstraintExpression.eval, fieldValue]
  | slotInverseExpr slot =>
      exact fieldInverse_canonical _
  | stableSelectorExpr bit =>
      simp [ProductionConstraintExpression.eval, fieldValue]
  | addExpr left right =>
      exact fieldAdd_canonical _ _
  | subExpr left right =>
      exact fieldSub_canonical _ _
  | mulExpr left right =>
      exact fieldMul_canonical _ _
  | negExpr value =>
      exact fieldNeg_canonical _

private theorem linearConstraintValue_canonical
    (statement : Statement)
    (witness : Witness)
    (constraint : Nat) :
    fieldValue (linearConstraintValue statement witness constraint) =
      linearConstraintValue statement witness constraint := by
  unfold linearConstraintValue
  let start := statement.linearTermOffsets.getD constraint 0
  let stop := statement.linearTermOffsets.getD (constraint + 1) start
  let termValue := fun relativeTerm =>
    let term := start + relativeTerm
    fieldMul (statement.linearTermCoefficients.getD term 0)
      (witness.getD (statement.linearTermIndices.getD term 0) 0)
  change
    fieldValue ((List.range (stop - start)).foldl
      (fun accumulator relativeTerm => fieldAdd accumulator (termValue relativeTerm)) 0) = _
  rw [← List.foldl_map]
  apply fieldValue_foldl_fieldAdd
  simp [fieldValue]

private theorem linearConstraintValue_cast
    (statement : Statement)
    (witness : Witness)
    (constraint : Nat) :
    toGoldilocks (linearConstraintValue statement witness constraint) =
      let start := statement.linearTermOffsets.getD constraint 0
      let stop := statement.linearTermOffsets.getD (constraint + 1) start
      ((List.range (stop - start)).map fun relativeTerm =>
        let term := start + relativeTerm
        toGoldilocks (statement.linearTermCoefficients.getD term 0) *
          toGoldilocks
            (witness.getD (statement.linearTermIndices.getD term 0) 0)).sum := by
  unfold linearConstraintValue
  let start := statement.linearTermOffsets.getD constraint 0
  let stop := statement.linearTermOffsets.getD (constraint + 1) start
  let termValue := fun relativeTerm =>
    let term := start + relativeTerm
    fieldMul (statement.linearTermCoefficients.getD term 0)
      (witness.getD (statement.linearTermIndices.getD term 0) 0)
  change
    toGoldilocks ((List.range (stop - start)).foldl
      (fun accumulator relativeTerm => fieldAdd accumulator (termValue relativeTerm)) 0) = _
  rw [← List.foldl_map]
  rw [toGoldilocks_foldl_fieldAdd]
  simp only [toGoldilocks, Nat.cast_zero, zero_add]
  apply congrArg List.sum
  rw [List.map_map]
  apply List.map_congr_left
  intro relativeTerm relativeTermMembership
  simp only [Function.comp_apply, termValue]
  exact toGoldilocks_fieldMul _ _

private theorem guarded_linear_term_encode
    (statement : Statement)
    (witness : Witness)
    (witnessLength : witness.length = witnessCellCount statement)
    (index coefficient : Nat) :
    (if index < witnessCellCount statement then toGoldilocks coefficient else 0) *
        assignmentAt (encodeProgram statement witness) index =
      toGoldilocks coefficient * toGoldilocks (witness.getD index 0) := by
  by_cases indexBound : index < witnessCellCount statement
  · simp [indexBound, assignmentAt_encodeProgram_witness]
  · have witnessIndexBound : ¬ index < witness.length := by
      simpa [witnessLength] using indexBound
    simp [indexBound, List.getD, witnessIndexBound, toGoldilocks]

private theorem linearConstraintTerms_encode_sum
    (statement : Statement)
    (witness : Witness)
    (witnessLength : witness.length = witnessCellCount statement)
    (constraint : Nat) :
    ((linearConstraintTerms statement constraint).map fun term =>
      term.2 * assignmentAt (encodeProgram statement witness) term.1).sum =
      toGoldilocks (linearConstraintValue statement witness constraint) := by
  rw [linearConstraintValue_cast]
  simp only [linearConstraintTerms, List.map_map]
  apply congrArg List.sum
  apply List.map_congr_left
  intro relativeTerm relativeTermMembership
  simp only [Function.comp_apply]
  exact guarded_linear_term_encode statement witness witnessLength _ _

private theorem linearEquation_satisfied_iff
    (statement : Statement)
    (constraint : Nat)
    (assignment : Fin (programVariableCount statement) → Goldilocks) :
    (linearEquation statement constraint).Satisfied assignment ↔
      ((linearConstraintTerms statement constraint).map fun term =>
        term.2 * assignmentAt assignment term.1).sum =
        toGoldilocks (statement.linearTargets.getD constraint 0) := by
  simp only [Equation.Satisfied, linearEquation, zeroForm_eval, affineCombination_eval,
    zero_mul, zero_add]
  rw [show
      -toGoldilocks (statement.linearTargets.getD constraint 0) +
          ((linearConstraintTerms statement constraint).map fun term =>
            term.2 * assignmentAt assignment term.1).sum =
        ((linearConstraintTerms statement constraint).map fun term =>
            term.2 * assignmentAt assignment term.1).sum -
          toGoldilocks (statement.linearTargets.getD constraint 0) by ring]
  exact sub_eq_zero

private theorem linearEquation_encode_iff
    (statement : Statement)
    (witness : Witness)
    (witnessLength : witness.length = witnessCellCount statement)
    (constraint : Nat) :
    (linearEquation statement constraint).Satisfied (encodeProgram statement witness) ↔
      linearConstraintEquation statement witness constraint := by
  rw [linearEquation_satisfied_iff]
  have castValue :=
    linearConstraintTerms_encode_sum statement witness witnessLength constraint
  constructor
  · intro rowEquation
    have castEquation :
        toGoldilocks (linearConstraintValue statement witness constraint) =
          toGoldilocks (statement.linearTargets.getD constraint 0) := by
      rw [← castValue]
      exact rowEquation
    have canonicalEquation := congrArg fromGoldilocks castEquation
    simpa [linearConstraintEquation, fromGoldilocks_toGoldilocks,
      linearConstraintValue_canonical] using canonicalEquation
  · intro equation
    calc
      ((linearConstraintTerms statement constraint).map fun term =>
          term.2 * assignmentAt (encodeProgram statement witness) term.1).sum =
          toGoldilocks (linearConstraintValue statement witness constraint) := castValue
      _ = toGoldilocks (statement.linearTargets.getD constraint 0) :=
        by
          simpa only [toGoldilocks_fieldValue] using congrArg toGoldilocks equation

private theorem sparseTableWellFormed_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    statement.sparseTableWellFormedB = true := by
  simp only [ProductionConstraintMapBound, productionConstraintMapBoundB,
    Bool.and_eq_true] at mapBound
  exact mapBound.1.1.1.1.2

private theorem expressionProgramWellFormed_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    expressionProgramWellFormedB statement = true := by
  have sparse := sparseTableWellFormed_of_mapBound mapBound
  simp only [ProductionConstraintMap.sparseTableWellFormedB,
    Bool.and_eq_true] at sparse
  exact sparse.1.1.2

private theorem expressionWellFormedAt_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement)
    (expression : Nat)
    (expressionBound : expression < statement.nonlinearExpressions.length) :
    statement.nonlinearExpressions[expression].wellFormedAt
      statement.publicValueCount statement.lppcRowCount expression = true := by
  have checked := expressionProgramWellFormed_of_mapBound mapBound
  simp only [expressionProgramWellFormedB] at checked
  have zipBound : expression < statement.nonlinearExpressions.zipIdx.length := by
    simpa using expressionBound
  have selected := (List.all_eq_true.mp checked)
    (statement.nonlinearExpressions.zipIdx[expression])
    (List.getElem_mem zipBound)
  simpa [List.getElem_zipIdx] using selected

private theorem expressionReferencesBound_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    ProductionExpressionReferencesBound statement.nonlinearExpressions := by
  intro expression expressionBound reference membership
  have wellFormed := expressionWellFormedAt_of_mapBound
    mapBound expression expressionBound
  have checked :
      (statement.nonlinearExpressions[expression].references).all
        (fun selected => decide (selected < expression)) = true := by
    cases selected : statement.nonlinearExpressions[expression] <;>
      simp [selected, ProductionConstraintExpression.wellFormedAt,
        ProductionConstraintExpression.references] at wellFormed ⊢ <;>
      assumption
  have referenceChecked := (List.all_eq_true.mp checked) reference membership
  exact of_decide_eq_true referenceChecked

private theorem nonlinearExpressionLength_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    statement.nonlinearExpressions.length = statement.nonlinearExpressionCount := by
  have sparse := sparseTableWellFormed_of_mapBound mapBound
  simp only [ProductionConstraintMap.sparseTableWellFormedB,
    Bool.and_eq_true] at sparse
  exact of_decide_eq_true sparse.1.1.1.1.1.2

private theorem nonlinearRootLength_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    statement.nonlinearConstraintRoots.length = statement.nonlinearConstraintCount := by
  have sparse := sparseTableWellFormed_of_mapBound mapBound
  simp only [ProductionConstraintMap.sparseTableWellFormedB,
    Bool.and_eq_true] at sparse
  exact of_decide_eq_true sparse.1.1.1.1.2

private theorem nonlinearRootBound_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement)
    (constraint : Nat)
    (constraintBound : constraint < statement.nonlinearConstraintCount) :
    statement.nonlinearConstraintRoots.getD constraint 0 <
      statement.nonlinearExpressionCount := by
  have rootLength := nonlinearRootLength_of_mapBound mapBound
  have rootListBound : constraint < statement.nonlinearConstraintRoots.length := by
    simpa [rootLength] using constraintBound
  have sparse := sparseTableWellFormed_of_mapBound mapBound
  simp only [ProductionConstraintMap.sparseTableWellFormedB,
    Bool.and_eq_true] at sparse
  have rootsChecked := sparse.1.1.1.2
  have selected := (List.all_eq_true.mp rootsChecked)
    statement.nonlinearConstraintRoots[constraint]
    (List.getElem_mem rootListBound)
  simpa [List.getD, rootListBound] using of_decide_eq_true selected

private theorem expressionValue_equation
    (statement : Statement)
    (witness : Witness)
    (mapBound : ProductionConstraintMapBound statement)
    (lane expression : Nat)
    (expressionBound : expression < statement.nonlinearExpressions.length) :
    expressionValue statement witness lane expression =
      statement.nonlinearExpressions[expression].eval statement.publicValues
        (witnessLaneRows statement witness lane)
        (evalExpressionProgram statement.publicValues
          (witnessLaneRows statement witness lane) statement.nonlinearExpressions) := by
  have referencesBound := expressionReferencesBound_of_mapBound mapBound
  have referencesChecked :
      (statement.nonlinearExpressions[expression].references).all
        (fun reference => decide (reference < expression)) = true := by
    rw [List.all_eq_true]
    intro reference membership
    exact decide_eq_true
      (referencesBound expression expressionBound reference membership)
  have equation := eval_expression_program_equation statement.publicValues
    (witnessLaneRows statement witness lane) statement.nonlinearExpressions
    expression expressionBound referencesChecked
  have valuesBound :
      expression <
        (evalExpressionProgram statement.publicValues
          (witnessLaneRows statement witness lane) statement.nonlinearExpressions).size := by
    rw [eval_expression_program_size]
    exact expressionBound
  simpa [expressionValue, Array.getD, valuesBound] using equation

private theorem witnessLaneRows_getD
    (statement : Statement)
    (witness : Witness)
    (witnessLength : witness.length = witnessCellCount statement)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (index : Nat) :
    (witnessLaneRows statement witness lane).getD index 0 =
      witness.getD (index * statement.lppcPackingFactor + lane) 0 := by
  by_cases indexBound : index < statement.lppcRowCount
  · simp [witnessLaneRows, List.getD, indexBound]
  · have packingPositive : 0 < statement.lppcPackingFactor :=
      Nat.zero_lt_of_lt laneBound
    have flattenedNotBound :
        ¬ index * statement.lppcPackingFactor + lane < witness.length := by
      rw [witnessLength]
      simp only [witnessCellCount]
      apply Nat.not_lt.mpr
      have rowLe : statement.lppcRowCount ≤ index := Nat.le_of_not_gt indexBound
      have productLe :
          statement.lppcRowCount * statement.lppcPackingFactor ≤
            index * statement.lppcPackingFactor :=
        Nat.mul_le_mul_right statement.lppcPackingFactor rowLe
      exact productLe.trans (Nat.le_add_right _ _)
    simp [witnessLaneRows, List.getD, indexBound, flattenedNotBound]

private theorem witnessFlatIndex_lt
    (statement : Statement)
    (lane index : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (indexBound : index < statement.lppcRowCount) :
    index * statement.lppcPackingFactor + lane < witnessCellCount statement := by
  have indexSuccessorBound : index + 1 ≤ statement.lppcRowCount :=
    Nat.succ_le_iff.mpr indexBound
  change
    index * statement.lppcPackingFactor + lane <
      statement.lppcRowCount * statement.lppcPackingFactor
  calc
    index * statement.lppcPackingFactor + lane <
        index * statement.lppcPackingFactor + statement.lppcPackingFactor :=
      Nat.add_lt_add_left laneBound _
    _ = (index + 1) * statement.lppcPackingFactor := by
      simp [Nat.add_mul, Nat.add_comm]
    _ ≤ statement.lppcRowCount * statement.lppcPackingFactor :=
      Nat.mul_le_mul_right statement.lppcPackingFactor indexSuccessorBound

private theorem expressionEquation_encode_satisfied
    (statement : Statement)
    (witness : Witness)
    (mapBound : ProductionConstraintMapBound statement)
    (witnessLength : witness.length = witnessCellCount statement)
    (lane expression : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (expressionBound : expression < statement.nonlinearExpressionCount) :
    (expressionEquation statement lane expression).Satisfied
      (encodeProgram statement witness) := by
  have expressionLength := nonlinearExpressionLength_of_mapBound mapBound
  have expressionListBound : expression < statement.nonlinearExpressions.length := by
    simpa [expressionLength] using expressionBound
  have semantic := expressionValue_equation statement witness mapBound lane expression
    expressionListBound
  have targetValue := assignmentAt_encodeProgram_expression statement witness lane expression
    laneBound expressionBound
  have selected :
      statement.nonlinearExpressions.getD expression (.constExpr 1) =
        statement.nonlinearExpressions[expression] := by
    simp [List.getD, expressionListBound]
  unfold expressionEquation
  rw [selected]
  cases expressionCase : statement.nonlinearExpressions[expression] with
  | constExpr value =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      apply (constantEquation_satisfied_iff statement _ _ _).2
      calc
        assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane expression) =
            toGoldilocks (expressionValue statement witness lane expression) := targetValue
        _ = toGoldilocks (fieldValue value) := congrArg toGoldilocks semantic
        _ = toGoldilocks value := toGoldilocks_fieldValue value
  | publicExpr index =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      apply (constantEquation_satisfied_iff statement _ _ _).2
      exact targetValue.trans (congrArg toGoldilocks semantic)
  | witnessExpr index =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      have wellFormed := expressionWellFormedAt_of_mapBound
        mapBound expression expressionListBound
      simp [expressionCase, ProductionConstraintExpression.wellFormedAt] at wellFormed
      have sourceBound := witnessFlatIndex_lt statement lane index laneBound wellFormed
      have sourceValue := assignmentAt_encodeProgram_witness statement witness
        (index * statement.lppcPackingFactor + lane) sourceBound
      apply (copyEquation_satisfied_iff statement _ _ _).2
      calc
        assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane expression) =
            toGoldilocks (expressionValue statement witness lane expression) := targetValue
        _ = toGoldilocks
            (fieldValue ((witnessLaneRows statement witness lane).getD index 0)) :=
          congrArg toGoldilocks semantic
        _ = toGoldilocks ((witnessLaneRows statement witness lane).getD index 0) :=
          toGoldilocks_fieldValue _
        _ = toGoldilocks
            (witness.getD (index * statement.lppcPackingFactor + lane) 0) :=
          congrArg toGoldilocks
            (witnessLaneRows_getD statement witness witnessLength lane laneBound index)
        _ = assignmentAt (encodeProgram statement witness)
            (index * statement.lppcPackingFactor + lane) := sourceValue.symm
  | slotInverseExpr slot =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      apply (constantEquation_satisfied_iff statement _ _ _).2
      exact targetValue.trans (congrArg toGoldilocks semantic)
  | stableSelectorExpr bit =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      apply (constantEquation_satisfied_iff statement _ _ _).2
      calc
        assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane expression) =
            toGoldilocks (expressionValue statement witness lane expression) := targetValue
        _ = toGoldilocks
            (fieldValue (stableSelectorSlot statement.publicValues / 2 ^ bit % 2)) :=
          congrArg toGoldilocks semantic
        _ = toGoldilocks (stableSelectorSlot statement.publicValues / 2 ^ bit % 2) :=
          toGoldilocks_fieldValue _
  | addExpr left right =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      change expressionValue statement witness lane expression =
        fieldAdd (expressionValue statement witness lane left)
          (expressionValue statement witness lane right) at semantic
      have references := expressionReferencesBound_of_mapBound mapBound
      have leftBound : left < statement.nonlinearExpressionCount :=
        (references expression expressionListBound left (by
          simp [expressionCase, ProductionConstraintExpression.references])).trans expressionBound
      have rightBound : right < statement.nonlinearExpressionCount :=
        (references expression expressionListBound right (by
          simp [expressionCase, ProductionConstraintExpression.references])).trans expressionBound
      have leftValue := assignmentAt_encodeProgram_expression statement witness lane left
        laneBound leftBound
      have rightValue := assignmentAt_encodeProgram_expression statement witness lane right
        laneBound rightBound
      apply (addEquation_satisfied_iff statement _ _ _ _).2
      calc
        assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane expression) =
            toGoldilocks (expressionValue statement witness lane expression) := targetValue
        _ = toGoldilocks (fieldAdd (expressionValue statement witness lane left)
            (expressionValue statement witness lane right)) := congrArg toGoldilocks semantic
        _ = toGoldilocks (expressionValue statement witness lane left) +
            toGoldilocks (expressionValue statement witness lane right) :=
          toGoldilocks_fieldAdd _ _
        _ = assignmentAt (encodeProgram statement witness)
              (expressionCellIndex statement lane left) +
            assignmentAt (encodeProgram statement witness)
              (expressionCellIndex statement lane right) :=
          congrArg₂ (fun leftValue rightValue => leftValue + rightValue)
            leftValue.symm rightValue.symm
  | subExpr left right =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      change expressionValue statement witness lane expression =
        fieldSub (expressionValue statement witness lane left)
          (expressionValue statement witness lane right) at semantic
      have references := expressionReferencesBound_of_mapBound mapBound
      have leftBound : left < statement.nonlinearExpressionCount :=
        (references expression expressionListBound left (by
          simp [expressionCase, ProductionConstraintExpression.references])).trans expressionBound
      have rightBound : right < statement.nonlinearExpressionCount :=
        (references expression expressionListBound right (by
          simp [expressionCase, ProductionConstraintExpression.references])).trans expressionBound
      have leftValue := assignmentAt_encodeProgram_expression statement witness lane left
        laneBound leftBound
      have rightValue := assignmentAt_encodeProgram_expression statement witness lane right
        laneBound rightBound
      apply (subEquation_satisfied_iff statement _ _ _ _).2
      calc
        assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane expression) =
            toGoldilocks (expressionValue statement witness lane expression) := targetValue
        _ = toGoldilocks (fieldSub (expressionValue statement witness lane left)
            (expressionValue statement witness lane right)) := congrArg toGoldilocks semantic
        _ = toGoldilocks (expressionValue statement witness lane left) -
            toGoldilocks (expressionValue statement witness lane right) :=
          toGoldilocks_fieldSub _ _
        _ = assignmentAt (encodeProgram statement witness)
              (expressionCellIndex statement lane left) -
            assignmentAt (encodeProgram statement witness)
              (expressionCellIndex statement lane right) :=
          congrArg₂ (fun leftValue rightValue => leftValue - rightValue)
            leftValue.symm rightValue.symm
  | mulExpr left right =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      change expressionValue statement witness lane expression =
        fieldMul (expressionValue statement witness lane left)
          (expressionValue statement witness lane right) at semantic
      have references := expressionReferencesBound_of_mapBound mapBound
      have leftBound : left < statement.nonlinearExpressionCount :=
        (references expression expressionListBound left (by
          simp [expressionCase, ProductionConstraintExpression.references])).trans expressionBound
      have rightBound : right < statement.nonlinearExpressionCount :=
        (references expression expressionListBound right (by
          simp [expressionCase, ProductionConstraintExpression.references])).trans expressionBound
      have leftValue := assignmentAt_encodeProgram_expression statement witness lane left
        laneBound leftBound
      have rightValue := assignmentAt_encodeProgram_expression statement witness lane right
        laneBound rightBound
      apply (mulEquation_satisfied_iff statement _ _ _ _).2
      calc
        assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane expression) =
            toGoldilocks (expressionValue statement witness lane expression) := targetValue
        _ = toGoldilocks (fieldMul (expressionValue statement witness lane left)
            (expressionValue statement witness lane right)) := congrArg toGoldilocks semantic
        _ = toGoldilocks (expressionValue statement witness lane left) *
            toGoldilocks (expressionValue statement witness lane right) :=
          toGoldilocks_fieldMul _ _
        _ = assignmentAt (encodeProgram statement witness)
              (expressionCellIndex statement lane left) *
            assignmentAt (encodeProgram statement witness)
              (expressionCellIndex statement lane right) :=
          congrArg₂ (fun leftValue rightValue => leftValue * rightValue)
            leftValue.symm rightValue.symm
  | negExpr value =>
      simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
      change expressionValue statement witness lane expression =
        fieldNeg (expressionValue statement witness lane value) at semantic
      have references := expressionReferencesBound_of_mapBound mapBound
      have valueBound : value < statement.nonlinearExpressionCount :=
        (references expression expressionListBound value (by
          simp [expressionCase, ProductionConstraintExpression.references])).trans expressionBound
      have sourceValue := assignmentAt_encodeProgram_expression statement witness lane value
        laneBound valueBound
      apply (negEquation_satisfied_iff statement _ _ _).2
      calc
        assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane expression) =
            toGoldilocks (expressionValue statement witness lane expression) := targetValue
        _ = toGoldilocks (fieldNeg (expressionValue statement witness lane value)) :=
          congrArg toGoldilocks semantic
        _ = -toGoldilocks (expressionValue statement witness lane value) :=
          toGoldilocks_fieldNeg _
        _ = -assignmentAt (encodeProgram statement witness)
            (expressionCellIndex statement lane value) := congrArg Neg.neg sourceValue.symm

private theorem expressionValue_canonical
    (statement : Statement)
    (witness : Witness)
    (mapBound : ProductionConstraintMapBound statement)
    (lane expression : Nat)
    (expressionBound : expression < statement.nonlinearExpressionCount) :
    fieldValue (expressionValue statement witness lane expression) =
      expressionValue statement witness lane expression := by
  have expressionLength := nonlinearExpressionLength_of_mapBound mapBound
  have expressionListBound : expression < statement.nonlinearExpressions.length := by
    simpa [expressionLength] using expressionBound
  rw [expressionValue_equation statement witness mapBound lane expression expressionListBound]
  exact expressionEval_canonical _ _ _ _

private theorem nonlinearConstraintValue_eq_expressionValue
    (statement : Statement)
    (witness : Witness)
    (mapBound : ProductionConstraintMapBound statement)
    (lane constraint : Nat)
    (constraintBound : constraint < statement.nonlinearConstraintCount) :
    nonlinearConstraintValue statement witness lane constraint =
      expressionValue statement witness lane
        (statement.nonlinearConstraintRoots.getD constraint 0) := by
  have rootBound := nonlinearRootBound_of_mapBound mapBound constraint constraintBound
  have expressionLength := nonlinearExpressionLength_of_mapBound mapBound
  have arrayBound :
      statement.nonlinearConstraintRoots.getD constraint 0 <
        (evalExpressionProgram statement.publicValues
          (witnessLaneRows statement witness lane) statement.nonlinearExpressions).size := by
    rw [eval_expression_program_size, expressionLength]
    exact rootBound
  unfold nonlinearConstraintValue expressionValue
  dsimp only
  unfold Array.getD
  rw [dif_pos arrayBound, dif_pos arrayBound]

private theorem rootEquation_encode_iff
    (statement : Statement)
    (witness : Witness)
    (mapBound : ProductionConstraintMapBound statement)
    (lane constraint : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (constraintBound : constraint < statement.nonlinearConstraintCount) :
    (rootEquation statement lane constraint).Satisfied (encodeProgram statement witness) ↔
      nonlinearConstraintEquation statement witness lane constraint := by
  have rootBound := nonlinearRootBound_of_mapBound mapBound constraint constraintBound
  have targetValue := assignmentAt_encodeProgram_expression statement witness lane
    (statement.nonlinearConstraintRoots.getD constraint 0) laneBound rootBound
  have nonlinearValue := nonlinearConstraintValue_eq_expressionValue
    statement witness mapBound lane constraint constraintBound
  unfold rootEquation
  rw [constantEquation_satisfied_iff]
  constructor
  · intro rowZero
    have castZero :
        toGoldilocks
            (nonlinearConstraintValue statement witness lane constraint) = 0 := by
      rw [nonlinearValue]
      exact targetValue.symm.trans rowZero
    have canonicalZero := congrArg fromGoldilocks castZero
    have valueCanonical := expressionValue_canonical statement witness mapBound lane
      (statement.nonlinearConstraintRoots.getD constraint 0) rootBound
    rw [fromGoldilocks_toGoldilocks] at canonicalZero
    have zeroRepresentative : fromGoldilocks (0 : Goldilocks) = 0 := by
      simp [fromGoldilocks]
    rw [zeroRepresentative] at canonicalZero
    change nonlinearConstraintValue statement witness lane constraint = 0
    have nonlinearCanonical :
        fieldValue (nonlinearConstraintValue statement witness lane constraint) =
          nonlinearConstraintValue statement witness lane constraint := by
      rw [nonlinearValue]
      exact valueCanonical
    exact nonlinearCanonical.symm.trans canonicalZero
  · intro equation
    have naturalZero :
        nonlinearConstraintValue statement witness lane constraint = 0 := equation
    calc
      assignmentAt (encodeProgram statement witness)
          (expressionCellIndex statement lane
            (statement.nonlinearConstraintRoots.getD constraint 0)) =
          toGoldilocks (expressionValue statement witness lane
            (statement.nonlinearConstraintRoots.getD constraint 0)) := targetValue
      _ = toGoldilocks (nonlinearConstraintValue statement witness lane constraint) :=
        congrArg toGoldilocks nonlinearValue.symm
      _ = 0 := by rw [naturalZero]; rfl

/-- Honest production witnesses satisfy every row of the statement-specific quadratic program. -/
theorem program_complete
    (statement : Statement)
    (witness : Witness)
    (membership : (statement, witness) ∈ Relation) :
    (program statement).Satisfies (encodeProgram statement witness) := by
  have mapBound := membership.1
  have exactEvaluation := membership.2
  simp only [ExactProductionConstraintMapEvaluates,
    exactProductionConstraintMapEvaluatesB, Bool.and_eq_true] at exactEvaluation
  obtain ⟨exactEvaluation, nonlinearRows⟩ := exactEvaluation
  obtain ⟨exactEvaluation, linearRows⟩ := exactEvaluation
  obtain ⟨sparseWellFormed, witnessLengthDecision⟩ := exactEvaluation
  have witnessLength : witness.length = witnessCellCount statement := by
    simpa [witnessCellCount] using of_decide_eq_true witnessLengthDecision
  simp only [nonlinearProgramEvaluatesB, Bool.and_eq_true] at nonlinearRows
  obtain ⟨nonlinearCountDecision, nonlinearLanes⟩ := nonlinearRows
  have nonlinearCount : statement.nonlinearConstraintCount = 890 :=
    of_decide_eq_true nonlinearCountDecision
  intro row
  have rowBound : row.val < programRowCount statement := by
    have rowIsLt := row.isLt
    change row.val < programRowCount statement at rowIsLt
    exact rowIsLt
  change (equationAt statement row.val).Satisfied (encodeProgram statement witness)
  unfold equationAt
  by_cases linearBound : row.val < statement.linearConstraintCount
  · rw [if_pos linearBound]
    apply (linearEquation_encode_iff statement witness witnessLength row.val).2
    have evaluated := (List.all_eq_true.mp linearRows) row.val
      (List.mem_range.mpr linearBound)
    have evaluatedDecision :
        decide (linearConstraintValue statement witness row.val =
          fieldValue (statement.linearTargets.getD row.val 0)) = true := by
      simpa [linearConstraintEvaluatesB] using evaluated
    change linearConstraintValue statement witness row.val =
      fieldValue (statement.linearTargets.getD row.val 0)
    exact of_decide_eq_true evaluatedDecision
  · rw [if_neg linearBound]
    let nonlinearRow := row.val - statement.linearConstraintCount
    by_cases expressionRowBound : nonlinearRow < expressionRowCount statement
    · rw [if_pos expressionRowBound]
      dsimp only
      have expandedBound :
          nonlinearRow <
            statement.lppcPackingFactor * statement.nonlinearExpressionCount := by
        unfold expressionRowCount expressionCellCount at expressionRowBound
        exact expressionRowBound
      have expressionCountPositive : 0 < statement.nonlinearExpressionCount :=
        Nat.pos_of_lt_mul_left expandedBound
      have laneBound :
          nonlinearRow / statement.nonlinearExpressionCount <
            statement.lppcPackingFactor :=
        (Nat.div_lt_iff_lt_mul expressionCountPositive).2 expandedBound
      have expressionBound :
          nonlinearRow % statement.nonlinearExpressionCount <
            statement.nonlinearExpressionCount :=
        Nat.mod_lt _ expressionCountPositive
      exact expressionEquation_encode_satisfied statement witness mapBound witnessLength
        (nonlinearRow / statement.nonlinearExpressionCount)
        (nonlinearRow % statement.nonlinearExpressionCount) laneBound expressionBound
    · rw [if_neg expressionRowBound]
      dsimp only
      let rootRow := nonlinearRow - expressionRowCount statement
      have rootRowBound : rootRow < rootRowCount statement := by
        dsimp only [rootRow, nonlinearRow]
        unfold programRowCount at rowBound
        omega
      have expandedBound :
          rootRow < statement.lppcPackingFactor * statement.nonlinearConstraintCount := by
        simpa [rootRowCount] using rootRowBound
      have constraintCountPositive : 0 < statement.nonlinearConstraintCount :=
        Nat.pos_of_lt_mul_left expandedBound
      have laneBound :
          rootRow / statement.nonlinearConstraintCount < statement.lppcPackingFactor :=
        (Nat.div_lt_iff_lt_mul constraintCountPositive).2 expandedBound
      have constraintBound :
          rootRow % statement.nonlinearConstraintCount <
            statement.nonlinearConstraintCount :=
        Nat.mod_lt _ constraintCountPositive
      apply (rootEquation_encode_iff statement witness mapBound
        (rootRow / statement.nonlinearConstraintCount)
        (rootRow % statement.nonlinearConstraintCount) laneBound constraintBound).2
      have laneEvaluated := (List.all_eq_true.mp nonlinearLanes)
        (rootRow / statement.nonlinearConstraintCount) (List.mem_range.mpr laneBound)
      have allConstraints :
          (List.range statement.nonlinearConstraintCount).all
            (fun constraint => nonlinearConstraintEvaluatesB statement witness
              (rootRow / statement.nonlinearConstraintCount) constraint) = true := by
        simpa [nonlinearLaneEvaluatesB] using laneEvaluated
      have evaluated := (List.all_eq_true.mp allConstraints)
        (rootRow % statement.nonlinearConstraintCount)
        (List.mem_range.mpr constraintBound)
      have evaluatedDecision :
          decide (nonlinearConstraintValue statement witness
            (rootRow / statement.nonlinearConstraintCount)
            (rootRow % statement.nonlinearConstraintCount) = 0) = true := by
        simpa [nonlinearConstraintEvaluatesB] using evaluated
      change nonlinearConstraintValue statement witness
        (rootRow / statement.nonlinearConstraintCount)
        (rootRow % statement.nonlinearConstraintCount) = 0
      exact of_decide_eq_true evaluatedDecision

private def witnessCell
    (statement : Statement)
    (index : Fin (witnessCellCount statement)) :
    Fin (program statement).variableCount :=
  ⟨index.val, by
    change index.val < programVariableCount statement
    exact index.isLt.trans_le (Nat.le_add_right _ _)⟩

/-- Canonical extraction always returns exactly the production witness length. -/
def decodeProgram
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks) : Witness :=
  List.ofFn fun index : Fin (witnessCellCount statement) =>
    fromGoldilocks (assignment (witnessCell statement index))

theorem decodeProgram_length
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks) :
    (decodeProgram statement assignment).length = witnessCellCount statement := by
  simp [decodeProgram]

private theorem assignmentAt_decodeProgram_witness
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (index : Nat)
    (indexBound : index < witnessCellCount statement) :
    assignmentAt assignment index =
      toGoldilocks ((decodeProgram statement assignment).getD index 0) := by
  have variableBound : index < (program statement).variableCount := by
    change index < programVariableCount statement
    exact indexBound.trans_le (Nat.le_add_right _ _)
  unfold assignmentAt
  rw [dif_pos variableBound]
  simp [decodeProgram, List.getD, indexBound, witnessCell,
    toGoldilocks_fromGoldilocks]

private theorem guarded_linear_term_decode
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (index coefficient : Nat) :
    (if index < witnessCellCount statement then toGoldilocks coefficient else 0) *
        assignmentAt assignment index =
      toGoldilocks coefficient *
        toGoldilocks ((decodeProgram statement assignment).getD index 0) := by
  by_cases indexBound : index < witnessCellCount statement
  · simp [indexBound, assignmentAt_decodeProgram_witness]
  · have witnessIndexBound :
        ¬ index < (decodeProgram statement assignment).length := by
      rw [decodeProgram_length]
      exact indexBound
    simp [indexBound, List.getD, witnessIndexBound, toGoldilocks]

private theorem linearConstraintTerms_decode_sum
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (constraint : Nat) :
    ((linearConstraintTerms statement constraint).map fun term =>
      term.2 * assignmentAt assignment term.1).sum =
      toGoldilocks
        (linearConstraintValue statement (decodeProgram statement assignment) constraint) := by
  rw [linearConstraintValue_cast]
  simp only [linearConstraintTerms, List.map_map]
  apply congrArg List.sum
  apply List.map_congr_left
  intro relativeTerm relativeTermMembership
  simp only [Function.comp_apply]
  exact guarded_linear_term_decode statement assignment _ _

private theorem linearEquation_decode_iff
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (constraint : Nat) :
    (linearEquation statement constraint).Satisfied assignment ↔
      linearConstraintEquation statement (decodeProgram statement assignment) constraint := by
  rw [linearEquation_satisfied_iff]
  have castValue := linearConstraintTerms_decode_sum statement assignment constraint
  constructor
  · intro rowEquation
    have castEquation :
        toGoldilocks
            (linearConstraintValue statement (decodeProgram statement assignment) constraint) =
          toGoldilocks (statement.linearTargets.getD constraint 0) := by
      rw [← castValue]
      exact rowEquation
    have canonicalEquation := congrArg fromGoldilocks castEquation
    simpa [linearConstraintEquation, fromGoldilocks_toGoldilocks,
      linearConstraintValue_canonical] using canonicalEquation
  · intro equation
    calc
      ((linearConstraintTerms statement constraint).map fun term =>
          term.2 * assignmentAt assignment term.1).sum =
          toGoldilocks
            (linearConstraintValue statement (decodeProgram statement assignment) constraint) :=
        castValue
      _ = toGoldilocks (statement.linearTargets.getD constraint 0) := by
        simpa only [toGoldilocks_fieldValue] using congrArg toGoldilocks equation

private theorem program_satisfies_linearEquation
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (satisfied : (program statement).Satisfies assignment)
    (constraint : Nat)
    (constraintBound : constraint < statement.linearConstraintCount) :
    (linearEquation statement constraint).Satisfied assignment := by
  have rowBound : constraint < (program statement).rowCount := by
    change constraint < programRowCount statement
    unfold programRowCount
    omega
  have selected := satisfied ⟨constraint, rowBound⟩
  change (equationAt statement constraint).Satisfied assignment at selected
  unfold equationAt at selected
  rw [if_pos constraintBound] at selected
  exact selected

private theorem program_satisfies_expressionEquation
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (satisfied : (program statement).Satisfies assignment)
    (lane expression : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (expressionBound : expression < statement.nonlinearExpressionCount) :
    (expressionEquation statement lane expression).Satisfied assignment := by
  have expressionPositive : 0 < statement.nonlinearExpressionCount :=
    Nat.zero_lt_of_lt expressionBound
  let offset := lane * statement.nonlinearExpressionCount + expression
  have offsetBound : offset < expressionRowCount statement := by
    unfold offset expressionRowCount
    have laneSuccessorBound : lane + 1 ≤ statement.lppcPackingFactor :=
      Nat.succ_le_iff.mpr laneBound
    calc
      lane * statement.nonlinearExpressionCount + expression <
          lane * statement.nonlinearExpressionCount +
            statement.nonlinearExpressionCount :=
        Nat.add_lt_add_left expressionBound _
      _ = (lane + 1) * statement.nonlinearExpressionCount := by
        simp [Nat.add_mul, Nat.add_comm]
      _ ≤ statement.lppcPackingFactor * statement.nonlinearExpressionCount :=
        Nat.mul_le_mul_right statement.nonlinearExpressionCount laneSuccessorBound
  let rowIndex := statement.linearConstraintCount + offset
  have rowBound : rowIndex < (program statement).rowCount := by
    change rowIndex < programRowCount statement
    unfold rowIndex programRowCount
    omega
  have selected := satisfied ⟨rowIndex, rowBound⟩
  change (equationAt statement rowIndex).Satisfied assignment at selected
  have notLinear : ¬ rowIndex < statement.linearConstraintCount := by
    unfold rowIndex
    omega
  have subtraction : rowIndex - statement.linearConstraintCount = offset := by
    unfold rowIndex
    omega
  have laneDivision : offset / statement.nonlinearExpressionCount = lane := by
    unfold offset
    rw [Nat.mul_comm]
    simp [Nat.mul_add_div expressionPositive, Nat.div_eq_of_lt expressionBound]
  have expressionModulus : offset % statement.nonlinearExpressionCount = expression := by
    unfold offset
    exact Nat.mul_add_mod_of_lt expressionBound
  unfold equationAt at selected
  rw [if_neg notLinear] at selected
  dsimp only at selected
  rw [subtraction, if_pos offsetBound] at selected
  rw [laneDivision, expressionModulus] at selected
  exact selected

private theorem program_satisfies_rootEquation
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (satisfied : (program statement).Satisfies assignment)
    (lane constraint : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (constraintBound : constraint < statement.nonlinearConstraintCount) :
    (rootEquation statement lane constraint).Satisfied assignment := by
  have constraintPositive : 0 < statement.nonlinearConstraintCount :=
    Nat.zero_lt_of_lt constraintBound
  let offset := lane * statement.nonlinearConstraintCount + constraint
  have offsetBound : offset < rootRowCount statement := by
    unfold offset rootRowCount
    have laneSuccessorBound : lane + 1 ≤ statement.lppcPackingFactor :=
      Nat.succ_le_iff.mpr laneBound
    calc
      lane * statement.nonlinearConstraintCount + constraint <
          lane * statement.nonlinearConstraintCount +
            statement.nonlinearConstraintCount :=
        Nat.add_lt_add_left constraintBound _
      _ = (lane + 1) * statement.nonlinearConstraintCount := by
        simp [Nat.add_mul, Nat.add_comm]
      _ ≤ statement.lppcPackingFactor * statement.nonlinearConstraintCount :=
        Nat.mul_le_mul_right statement.nonlinearConstraintCount laneSuccessorBound
  let rowIndex :=
    statement.linearConstraintCount + expressionRowCount statement + offset
  have rowBound : rowIndex < (program statement).rowCount := by
    change rowIndex < programRowCount statement
    unfold rowIndex programRowCount
    omega
  have selected := satisfied ⟨rowIndex, rowBound⟩
  change (equationAt statement rowIndex).Satisfied assignment at selected
  have notLinear : ¬ rowIndex < statement.linearConstraintCount := by
    unfold rowIndex
    omega
  have firstSubtraction :
      rowIndex - statement.linearConstraintCount = expressionRowCount statement + offset := by
    unfold rowIndex
    omega
  have notExpression : ¬ expressionRowCount statement + offset < expressionRowCount statement := by
    omega
  have secondSubtraction :
      expressionRowCount statement + offset - expressionRowCount statement = offset := by
    omega
  have laneDivision : offset / statement.nonlinearConstraintCount = lane := by
    unfold offset
    rw [Nat.mul_comm]
    simp [Nat.mul_add_div constraintPositive, Nat.div_eq_of_lt constraintBound]
  have constraintModulus : offset % statement.nonlinearConstraintCount = constraint := by
    unfold offset
    exact Nat.mul_add_mod_of_lt constraintBound
  unfold equationAt at selected
  rw [if_neg notLinear] at selected
  dsimp only at selected
  rw [firstSubtraction, if_neg notExpression] at selected
  rw [secondSubtraction, laneDivision, constraintModulus] at selected
  exact selected

private theorem satisfyingAssignment_expressionValue
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (mapBound : ProductionConstraintMapBound statement)
    (satisfied : (program statement).Satisfies assignment)
    (lane : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (expression : Nat)
    (expressionBound : expression < statement.nonlinearExpressionCount) :
    assignmentAt assignment (expressionCellIndex statement lane expression) =
      toGoldilocks
        (expressionValue statement (decodeProgram statement assignment) lane expression) := by
  induction expression using Nat.strongRecOn with
  | ind expression inductionHypothesis =>
      have expressionLength := nonlinearExpressionLength_of_mapBound mapBound
      have expressionListBound : expression < statement.nonlinearExpressions.length := by
        simpa [expressionLength] using expressionBound
      have decodedLength := decodeProgram_length statement assignment
      have semantic := expressionValue_equation statement
        (decodeProgram statement assignment) mapBound lane expression expressionListBound
      have rowSatisfied := program_satisfies_expressionEquation statement assignment satisfied
        lane expression laneBound expressionBound
      have selected :
          statement.nonlinearExpressions.getD expression (.constExpr 1) =
            statement.nonlinearExpressions[expression] := by
        simp [List.getD, expressionListBound]
      have rowEquation :=
        (expressionEquation_satisfied_iff statement lane expression assignment).1 rowSatisfied
      unfold expressionAssignmentValue at rowEquation
      rw [selected] at rowEquation
      cases expressionCase : statement.nonlinearExpressions[expression] with
      | constExpr value =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          simp only [expressionCase] at rowEquation
          calc
            assignmentAt assignment (expressionCellIndex statement lane expression) =
                toGoldilocks value := rowEquation
            _ = toGoldilocks (fieldValue value) := (toGoldilocks_fieldValue value).symm
            _ = toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane expression) :=
              congrArg toGoldilocks semantic.symm

      | publicExpr index =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          simp only [expressionCase] at rowEquation
          exact rowEquation.trans (congrArg toGoldilocks semantic.symm)
      | witnessExpr index =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          have wellFormed := expressionWellFormedAt_of_mapBound
            mapBound expression expressionListBound
          simp [expressionCase, ProductionConstraintExpression.wellFormedAt] at wellFormed
          have sourceBound := witnessFlatIndex_lt statement lane index laneBound wellFormed
          have sourceValue := assignmentAt_decodeProgram_witness statement assignment
            (index * statement.lppcPackingFactor + lane) sourceBound
          simp only [expressionCase] at rowEquation
          calc
            assignmentAt assignment (expressionCellIndex statement lane expression) =
                assignmentAt assignment
                  (index * statement.lppcPackingFactor + lane) := rowEquation
            _ = toGoldilocks
                ((decodeProgram statement assignment).getD
                  (index * statement.lppcPackingFactor + lane) 0) := sourceValue
            _ = toGoldilocks
                ((witnessLaneRows statement (decodeProgram statement assignment) lane).getD
                  index 0) :=
              congrArg toGoldilocks
                (witnessLaneRows_getD statement (decodeProgram statement assignment)
                  decodedLength lane laneBound index).symm
            _ = toGoldilocks
                (fieldValue
                  ((witnessLaneRows statement (decodeProgram statement assignment) lane).getD
                    index 0)) :=
              (toGoldilocks_fieldValue _).symm
            _ = toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane expression) :=
              congrArg toGoldilocks semantic.symm
      | slotInverseExpr slot =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          simp only [expressionCase] at rowEquation
          exact rowEquation.trans (congrArg toGoldilocks semantic.symm)
      | stableSelectorExpr bit =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          simp only [expressionCase] at rowEquation
          calc
            assignmentAt assignment (expressionCellIndex statement lane expression) =
                toGoldilocks (stableSelectorSlot statement.publicValues / 2 ^ bit % 2) :=
              rowEquation
            _ = toGoldilocks
                (fieldValue (stableSelectorSlot statement.publicValues / 2 ^ bit % 2)) :=
              (toGoldilocks_fieldValue _).symm
            _ = toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane expression) :=
              congrArg toGoldilocks semantic.symm
      | addExpr left right =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          change expressionValue statement (decodeProgram statement assignment) lane expression =
            fieldAdd
              (expressionValue statement (decodeProgram statement assignment) lane left)
              (expressionValue statement (decodeProgram statement assignment) lane right)
            at semantic
          have references := expressionReferencesBound_of_mapBound mapBound
          have leftStrict : left < expression :=
            references expression expressionListBound left (by
              simp [expressionCase, ProductionConstraintExpression.references])
          have rightStrict : right < expression :=
            references expression expressionListBound right (by
              simp [expressionCase, ProductionConstraintExpression.references])
          have leftBound : left < statement.nonlinearExpressionCount :=
            leftStrict.trans expressionBound
          have rightBound : right < statement.nonlinearExpressionCount :=
            rightStrict.trans expressionBound
          have leftExtracted := inductionHypothesis left leftStrict leftBound
          have rightExtracted := inductionHypothesis right rightStrict rightBound
          simp only [expressionCase] at rowEquation
          calc
            assignmentAt assignment (expressionCellIndex statement lane expression) =
                assignmentAt assignment (expressionCellIndex statement lane left) +
                  assignmentAt assignment (expressionCellIndex statement lane right) := rowEquation
            _ = toGoldilocks
                  (expressionValue statement (decodeProgram statement assignment) lane left) +
                toGoldilocks
                  (expressionValue statement (decodeProgram statement assignment) lane right) :=
              congrArg₂ (fun leftValue rightValue => leftValue + rightValue)
                leftExtracted rightExtracted
            _ = toGoldilocks
                (fieldAdd
                  (expressionValue statement (decodeProgram statement assignment) lane left)
                  (expressionValue statement (decodeProgram statement assignment) lane right)) :=
              (toGoldilocks_fieldAdd _ _).symm
            _ = toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane expression) :=
              congrArg toGoldilocks semantic.symm
      | subExpr left right =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          change expressionValue statement (decodeProgram statement assignment) lane expression =
            fieldSub
              (expressionValue statement (decodeProgram statement assignment) lane left)
              (expressionValue statement (decodeProgram statement assignment) lane right)
            at semantic
          have references := expressionReferencesBound_of_mapBound mapBound
          have leftStrict : left < expression :=
            references expression expressionListBound left (by
              simp [expressionCase, ProductionConstraintExpression.references])
          have rightStrict : right < expression :=
            references expression expressionListBound right (by
              simp [expressionCase, ProductionConstraintExpression.references])
          have leftBound : left < statement.nonlinearExpressionCount :=
            leftStrict.trans expressionBound
          have rightBound : right < statement.nonlinearExpressionCount :=
            rightStrict.trans expressionBound
          have leftExtracted := inductionHypothesis left leftStrict leftBound
          have rightExtracted := inductionHypothesis right rightStrict rightBound
          simp only [expressionCase] at rowEquation
          calc
            assignmentAt assignment (expressionCellIndex statement lane expression) =
                assignmentAt assignment (expressionCellIndex statement lane left) -
                  assignmentAt assignment (expressionCellIndex statement lane right) := rowEquation
            _ = toGoldilocks
                  (expressionValue statement (decodeProgram statement assignment) lane left) -
                toGoldilocks
                  (expressionValue statement (decodeProgram statement assignment) lane right) :=
              congrArg₂ (fun leftValue rightValue => leftValue - rightValue)
                leftExtracted rightExtracted
            _ = toGoldilocks
                (fieldSub
                  (expressionValue statement (decodeProgram statement assignment) lane left)
                  (expressionValue statement (decodeProgram statement assignment) lane right)) :=
              (toGoldilocks_fieldSub _ _).symm
            _ = toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane expression) :=
              congrArg toGoldilocks semantic.symm
      | mulExpr left right =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          change expressionValue statement (decodeProgram statement assignment) lane expression =
            fieldMul
              (expressionValue statement (decodeProgram statement assignment) lane left)
              (expressionValue statement (decodeProgram statement assignment) lane right)
            at semantic
          have references := expressionReferencesBound_of_mapBound mapBound
          have leftStrict : left < expression :=
            references expression expressionListBound left (by
              simp [expressionCase, ProductionConstraintExpression.references])
          have rightStrict : right < expression :=
            references expression expressionListBound right (by
              simp [expressionCase, ProductionConstraintExpression.references])
          have leftBound : left < statement.nonlinearExpressionCount :=
            leftStrict.trans expressionBound
          have rightBound : right < statement.nonlinearExpressionCount :=
            rightStrict.trans expressionBound
          have leftExtracted := inductionHypothesis left leftStrict leftBound
          have rightExtracted := inductionHypothesis right rightStrict rightBound
          simp only [expressionCase] at rowEquation
          calc
            assignmentAt assignment (expressionCellIndex statement lane expression) =
                assignmentAt assignment (expressionCellIndex statement lane left) *
                  assignmentAt assignment (expressionCellIndex statement lane right) := rowEquation
            _ = toGoldilocks
                  (expressionValue statement (decodeProgram statement assignment) lane left) *
                toGoldilocks
                  (expressionValue statement (decodeProgram statement assignment) lane right) :=
              congrArg₂ (fun leftValue rightValue => leftValue * rightValue)
                leftExtracted rightExtracted
            _ = toGoldilocks
                (fieldMul
                  (expressionValue statement (decodeProgram statement assignment) lane left)
                  (expressionValue statement (decodeProgram statement assignment) lane right)) :=
              (toGoldilocks_fieldMul _ _).symm
            _ = toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane expression) :=
              congrArg toGoldilocks semantic.symm
      | negExpr value =>
          simp only [expressionCase, ProductionConstraintExpression.eval] at semantic
          change expressionValue statement (decodeProgram statement assignment) lane expression =
            fieldNeg
              (expressionValue statement (decodeProgram statement assignment) lane value)
            at semantic
          have references := expressionReferencesBound_of_mapBound mapBound
          have valueStrict : value < expression :=
            references expression expressionListBound value (by
              simp [expressionCase, ProductionConstraintExpression.references])
          have valueBound : value < statement.nonlinearExpressionCount :=
            valueStrict.trans expressionBound
          have valueExtracted := inductionHypothesis value valueStrict valueBound
          simp only [expressionCase] at rowEquation
          calc
            assignmentAt assignment (expressionCellIndex statement lane expression) =
                -assignmentAt assignment (expressionCellIndex statement lane value) := rowEquation
            _ = -toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane value) :=
              congrArg Neg.neg valueExtracted
            _ = toGoldilocks
                (fieldNeg
                  (expressionValue statement (decodeProgram statement assignment) lane value)) :=
              (toGoldilocks_fieldNeg _).symm
            _ = toGoldilocks
                (expressionValue statement (decodeProgram statement assignment) lane expression) :=
              congrArg toGoldilocks semantic.symm

private theorem satisfyingAssignment_rootEquation
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (mapBound : ProductionConstraintMapBound statement)
    (satisfied : (program statement).Satisfies assignment)
    (lane constraint : Nat)
    (laneBound : lane < statement.lppcPackingFactor)
    (constraintBound : constraint < statement.nonlinearConstraintCount) :
    nonlinearConstraintEquation statement (decodeProgram statement assignment)
      lane constraint := by
  have rootBound := nonlinearRootBound_of_mapBound mapBound constraint constraintBound
  have rootRow := program_satisfies_rootEquation statement assignment satisfied
    lane constraint laneBound constraintBound
  unfold rootEquation at rootRow
  have rowZero := (constantEquation_satisfied_iff statement _ _ assignment).1 rootRow
  have extractedRoot := satisfyingAssignment_expressionValue statement assignment mapBound
    satisfied lane laneBound (statement.nonlinearConstraintRoots.getD constraint 0) rootBound
  have nonlinearValue := nonlinearConstraintValue_eq_expressionValue statement
    (decodeProgram statement assignment) mapBound lane constraint constraintBound
  have castZero :
      toGoldilocks
          (nonlinearConstraintValue statement (decodeProgram statement assignment)
            lane constraint) = 0 := by
    calc
      toGoldilocks
          (nonlinearConstraintValue statement (decodeProgram statement assignment)
            lane constraint) =
          toGoldilocks
            (expressionValue statement (decodeProgram statement assignment) lane
              (statement.nonlinearConstraintRoots.getD constraint 0)) :=
        congrArg toGoldilocks nonlinearValue
      _ = assignmentAt assignment
          (expressionCellIndex statement lane
            (statement.nonlinearConstraintRoots.getD constraint 0)) := extractedRoot.symm
      _ = 0 := rowZero
  have canonicalZero := congrArg fromGoldilocks castZero
  rw [fromGoldilocks_toGoldilocks] at canonicalZero
  have zeroRepresentative : fromGoldilocks (0 : Goldilocks) = 0 := by
    simp [fromGoldilocks]
  rw [zeroRepresentative] at canonicalZero
  have rootCanonical := expressionValue_canonical statement
    (decodeProgram statement assignment) mapBound lane
    (statement.nonlinearConstraintRoots.getD constraint 0) rootBound
  have nonlinearCanonical :
      fieldValue
          (nonlinearConstraintValue statement (decodeProgram statement assignment)
            lane constraint) =
        nonlinearConstraintValue statement (decodeProgram statement assignment)
          lane constraint := by
    rw [nonlinearValue]
    exact rootCanonical
  change nonlinearConstraintValue statement (decodeProgram statement assignment)
    lane constraint = 0
  exact nonlinearCanonical.symm.trans canonicalZero

private theorem nonlinearConstraintCount_of_mapBound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    statement.nonlinearConstraintCount = 890 := by
  have rootLength := nonlinearRootLength_of_mapBound mapBound
  have staticProgram := production_constraint_map_bound_uses_static_nonlinear_program mapBound
  calc
    statement.nonlinearConstraintCount = statement.nonlinearConstraintRoots.length :=
      rootLength.symm
    _ = productionNonlinearConstraintRoots.length := congrArg List.length staticProgram.2
    _ = 890 := production_nonlinear_root_count_is_exact

/-- Every satisfying quadratic-program assignment extracts to the exact production relation. -/
theorem program_sound
    (statement : Statement)
    (assignment : Fin (program statement).variableCount → Goldilocks)
    (mapBound : ProductionConstraintMapBound statement)
    (satisfied : (program statement).Satisfies assignment) :
    (statement, decodeProgram statement assignment) ∈ Relation := by
  refine ⟨mapBound, ?_⟩
  have witnessLength := decodeProgram_length statement assignment
  have linearRows :
      linearProgramEvaluatesB statement (decodeProgram statement assignment) = true := by
    unfold linearProgramEvaluatesB
    rw [List.all_eq_true]
    intro constraint constraintMembership
    have constraintBound := List.mem_range.mp constraintMembership
    have rowSatisfied := program_satisfies_linearEquation statement assignment satisfied
      constraint constraintBound
    have equation :=
      (linearEquation_decode_iff statement assignment constraint).1 rowSatisfied
    unfold linearConstraintEvaluatesB
    exact decide_eq_true equation
  have nonlinearCount := nonlinearConstraintCount_of_mapBound mapBound
  have nonlinearRows :
      nonlinearProgramEvaluatesB statement (decodeProgram statement assignment) = true := by
    unfold nonlinearProgramEvaluatesB
    rw [Bool.and_eq_true]
    refine ⟨decide_eq_true nonlinearCount, ?_⟩
    rw [List.all_eq_true]
    intro lane laneMembership
    have laneBound := List.mem_range.mp laneMembership
    unfold nonlinearLaneEvaluatesB
    rw [List.all_eq_true]
    intro constraint constraintMembership
    have constraintBound := List.mem_range.mp constraintMembership
    have equation := satisfyingAssignment_rootEquation statement assignment mapBound satisfied
      lane constraint laneBound constraintBound
    unfold nonlinearConstraintEvaluatesB
    exact decide_eq_true equation
  unfold ExactProductionConstraintMapEvaluates exactProductionConstraintMapEvaluatesB
  simp only [Bool.and_eq_true]
  exact ⟨⟨⟨sparseTableWellFormed_of_mapBound mapBound,
    decide_eq_true witnessLength⟩, linearRows⟩, nonlinearRows⟩

/-- Canonical CCS compiled from the exact statement-specific quadratic program. -/
def system (statement : Statement) : HegemonCrypto.CCS.System Goldilocks :=
  compile (program statement)

/-- Honest CCS assignment, including the compiler's forced constant-one cell. -/
def encode
    (statement : Statement)
    (witness : Witness) : Fin (system statement).variableCount → Goldilocks :=
  augmentAssignment (encodeProgram statement witness)

/-- Canonical witness extracted from an arbitrary CCS assignment. -/
def decode
    (statement : Statement)
    (assignment : Fin (system statement).variableCount → Goldilocks) : Witness :=
  decodeProgram statement (tailAssignment assignment)

theorem decode_length
    (statement : Statement)
    (assignment : Fin (system statement).variableCount → Goldilocks) :
    (decode statement assignment).length = witnessCellCount statement := by
  exact decodeProgram_length statement (tailAssignment assignment)

theorem system_satisfies_encode_iff
    (statement : Statement)
    (witness : Witness) :
    (system statement).Satisfies (encode statement witness) ↔
      (program statement).Satisfies (encodeProgram statement witness) := by
  exact compile_complete_iff (program statement) (encodeProgram statement witness)

/-- Relation membership gives a satisfying assignment for the exact compiled CCS. -/
theorem compile_complete
    (statement : Statement)
    (witness : Witness)
    (membership : (statement, witness) ∈ Relation) :
    (system statement).Satisfies (encode statement witness) := by
  apply (system_satisfies_encode_iff statement witness).2
  exact program_complete statement witness membership

/-- Every satisfying compiled CCS assignment canonically extracts an exact production witness. -/
theorem compile_sound
    (statement : Statement)
    (assignment : Fin (system statement).variableCount → Goldilocks)
    (mapBound : ProductionConstraintMapBound statement)
    (satisfied : (system statement).Satisfies assignment) :
    (statement, decode statement assignment) ∈ Relation := by
  have compiled := (compile_satisfies_iff (program statement) assignment).1 satisfied
  exact program_sound statement (tailAssignment assignment) mapBound compiled.2

/-- Checked witness for the exact statement-dependent production-to-CCS refinement. -/
def exactCCSRefinement : ExactCCSRefinement Goldilocks where
  system := system
  encode := encode
  decode := decode
  complete := compile_complete
  sound := compile_sound

/-- Both directions of the production CCS contract, exposed as one review theorem. -/
theorem production_ccs_exact
    (statement : Statement) :
    (∀ witness, (statement, witness) ∈ Relation →
      (system statement).Satisfies (encode statement witness)) ∧
    (∀ assignment, ProductionConstraintMapBound statement →
      (system statement).Satisfies assignment →
        (statement, decode statement assignment) ∈ Relation) := by
  exact ⟨compile_complete statement, compile_sound statement⟩

/-- Bounded fixture for the generated production template without materializing dense matrices. -/
theorem production_template_compiler_dimensions :
    (system productionConstraintMapTemplateBase).variableCount = 610561 ∧
      (system productionConstraintMapTemplateBase).rowCount = 640215 := by
  constructor <;> rfl

/-- Public canonicality fact needed when an extracted field value is reflected to a natural row. -/
theorem linear_constraint_value_is_canonical
    (statement : Statement)
    (witness : Witness)
    (constraint : Nat) :
    fieldValue (linearConstraintValue statement witness constraint) =
      linearConstraintValue statement witness constraint := by
  exact linearConstraintValue_canonical statement witness constraint

/-- Every bounded nonlinear root evaluates to a canonical Goldilocks representative. -/
theorem nonlinear_constraint_value_is_canonical
    (statement : Statement)
    (witness : Witness)
    (mapBound : ProductionConstraintMapBound statement)
    (lane constraint : Nat)
    (constraintBound : constraint < statement.nonlinearConstraintCount) :
    fieldValue (nonlinearConstraintValue statement witness lane constraint) =
      nonlinearConstraintValue statement witness lane constraint := by
  have rootBound := nonlinearRootBound_of_mapBound mapBound constraint constraintBound
  rw [nonlinearConstraintValue_eq_expressionValue statement witness mapBound lane constraint
    constraintBound]
  exact expressionValue_canonical statement witness mapBound lane
    (statement.nonlinearConstraintRoots.getD constraint 0) rootBound

/-- A bounded production map exposes the sparse-table well-formedness consumed by extraction. -/
theorem sparse_table_well_formed_of_map_bound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    statement.sparseTableWellFormedB = true := by
  exact sparseTableWellFormed_of_mapBound mapBound

/-- A bounded production map has exactly the deployed 890 nonlinear roots. -/
theorem nonlinear_constraint_count_of_map_bound
    {statement : Statement}
    (mapBound : ProductionConstraintMapBound statement) :
    statement.nonlinearConstraintCount = 890 := by
  exact nonlinearConstraintCount_of_mapBound mapBound

end HegemonCrypto.SmallWood.ProductionCCS
