import HegemonCrypto.SmallWoodV8Smz9SemanticBinding
import HegemonCrypto.SmallWoodProductionPolynomials

/-! Polynomial interpretation of the actual HGV8RP03 `FieldExpression` grammar.
Inverse and bit operations are specialized only at certified degree-zero inputs;
equality selection is specialized only at certified degree-zero comparisons.
No identification with the older production-expression grammar is assumed. -/

namespace HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials

open Polynomial
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

noncomputable section

def expressionPolynomial (pub : Nat → Goldilocks)
    (rows values : Nat → Goldilocks[X]) : FieldExpression → Goldilocks[X]
  | .constant n => C (n : Goldilocks)
  | .publicWord n => C (pub n)
  | .witnessRow n => rows n
  | .add a b => values a + values b
  | .sub a b => values a - values b
  | .mul a b => values a * values b
  | .neg a => -values a
  | .inverse a => C (fieldInverse ((values a).coeff 0).val : Goldilocks)
  | .selectEqual a b c d =>
      if (values a).coeff 0 = (values b).coeff 0 then values c else values d
  | .bit a b => C ((((values a).coeff 0).val / 2 ^ b) % 2 : Nat)

def expressionField (pub rows values : Nat → Goldilocks) : FieldExpression → Goldilocks
  | .constant n => n
  | .publicWord n => pub n
  | .witnessRow n => rows n
  | .add a b => values a + values b
  | .sub a b => values a - values b
  | .mul a b => values a * values b
  | .neg a => -values a
  | .inverse a => (fieldInverse (values a).val : Goldilocks)
  | .selectEqual a b c d => if values a = values b then values c else values d
  | .bit a b => (((values a).val / 2 ^ b) % 2 : Nat)

def expressionDegree (degree : Nat → Nat) : FieldExpression → Nat
  | .constant _ | .publicWord _ => 0
  | .witnessRow _ => 1
  | .add a b | .sub a b => max (degree a) (degree b)
  | .mul a b => degree a + degree b
  | .neg a => degree a
  | .inverse _ | .bit _ _ => 0
  | .selectEqual _ _ c d => max (degree c) (degree d)

def expressionSafe (degree : Nat → Nat) : FieldExpression → Prop
  | .inverse a | .bit a _ => degree a = 0
  | .selectEqual a b _ _ => degree a = 0 ∧ degree b = 0
  | _ => True

instance (degree : Nat → Nat) (expression : FieldExpression) :
    Decidable (expressionSafe degree expression) := by
  cases expression <;> unfold expressionSafe <;> infer_instance

theorem expression_degree (pub : Nat → Goldilocks)
    (rows values : Nat → Goldilocks[X]) (degree : Nat → Nat) (bound : Nat)
    (rowBound : ∀ n, (rows n).natDegree ≤ bound)
    (valueBound : ∀ n, (values n).natDegree ≤ degree n * bound)
    (expression : FieldExpression) :
    (expressionPolynomial pub rows values expression).natDegree ≤
      expressionDegree degree expression * bound := by
  cases expression with
  | constant n => simp [expressionPolynomial, expressionDegree]
  | publicWord n => simp [expressionPolynomial, expressionDegree]
  | witnessRow n => simpa [expressionPolynomial, expressionDegree] using rowBound n
  | add a b =>
      exact (natDegree_add_le _ _).trans (max_le
        ((valueBound a).trans (Nat.mul_le_mul_right _ (Nat.le_max_left _ _)))
        ((valueBound b).trans (Nat.mul_le_mul_right _ (Nat.le_max_right _ _))))
  | sub a b =>
      exact (natDegree_sub_le _ _).trans (max_le
        ((valueBound a).trans (Nat.mul_le_mul_right _ (Nat.le_max_left _ _)))
        ((valueBound b).trans (Nat.mul_le_mul_right _ (Nat.le_max_right _ _))))
  | mul a b =>
      exact natDegree_mul_le.trans ((Nat.add_le_add (valueBound a) (valueBound b)).trans
        (by simp [expressionDegree, Nat.add_mul]))
  | neg a => exact natDegree_neg_le_of_le (valueBound a)
  | inverse a => simp [expressionPolynomial, expressionDegree]
  | bit a b => simp [expressionPolynomial, expressionDegree]
  | selectEqual a b c d =>
      simp only [expressionPolynomial, expressionDegree]
      split
      · exact (valueBound c).trans (Nat.mul_le_mul_right _ (Nat.le_max_left _ _))
      · exact (valueBound d).trans (Nat.mul_le_mul_right _ (Nat.le_max_right _ _))

theorem degree_zero_eval (polynomial : Goldilocks[X]) (bound : polynomial.natDegree ≤ 0)
    (point : Goldilocks) : polynomial.coeff 0 = polynomial.eval point := by
  rw [Polynomial.eq_C_of_natDegree_le_zero bound]
  simp

theorem expression_commutes (pub : Nat → Goldilocks)
    (rows values : Nat → Goldilocks[X]) (degree : Nat → Nat) (bound : Nat)
    (valueBound : ∀ n, (values n).natDegree ≤ degree n * bound)
    (expression : FieldExpression) (safe : expressionSafe degree expression)
    (point : Goldilocks) :
    (expressionPolynomial pub rows values expression).eval point =
      expressionField pub (fun n => (rows n).eval point)
        (fun n => (values n).eval point) expression := by
  have constantAt : ∀ n, degree n = 0 → (values n).coeff 0 = (values n).eval point := by
    intro n zero
    apply degree_zero_eval
    simpa [zero] using valueBound n
  cases expression <;> simp only [expressionSafe] at safe
  all_goals simp [expressionPolynomial, expressionField, constantAt, safe]
  split <;> rfl

/-- Earlier-node projection makes the source DAG interpretation total without
    adding evaluator-equivalence or polynomial-existence assumptions. -/
def prior {α : Type} [Zero α] (node : Nat) (values : (i : Nat) → i < node → α)
    (i : Nat) : α := if h : i < node then values i h else 0

def polynomialAt (program : List FieldExpression) (pub : Nat → Goldilocks)
    (rows : Nat → Goldilocks[X]) : Nat → Goldilocks[X] :=
  Nat.strongRec fun node earlier =>
    match program[node]? with
    | none => 0
    | some expression => expressionPolynomial pub rows (prior node earlier) expression

def fieldAt (program : List FieldExpression) (pub rows : Nat → Goldilocks) : Nat → Goldilocks :=
  Nat.strongRec fun node earlier =>
    match program[node]? with
    | none => 0
    | some expression => expressionField pub rows (prior node earlier) expression

theorem polynomialAt_eq (program : List FieldExpression) (pub : Nat → Goldilocks)
    (rows : Nat → Goldilocks[X]) (node : Nat) :
    polynomialAt program pub rows node =
      match program[node]? with
      | none => 0
      | some expression => expressionPolynomial pub rows
          (fun i => if i < node then polynomialAt program pub rows i else 0) expression := by
  unfold polynomialAt
  rw [Nat.strongRec_eq]
  rfl

theorem fieldAt_eq (program : List FieldExpression) (pub rows : Nat → Goldilocks)
    (node : Nat) :
    fieldAt program pub rows node =
      match program[node]? with
      | none => 0
      | some expression => expressionField pub rows
          (fun i => if i < node then fieldAt program pub rows i else 0) expression := by
  unfold fieldAt
  rw [Nat.strongRec_eq]
  rfl

def DegreeCertificate (program : List FieldExpression) (degree : Nat → Nat) : Prop :=
  ∀ node expression, program[node]? = some expression →
    expressionDegree degree expression ≤ degree node ∧ expressionSafe degree expression

theorem polynomialAt_degree (program : List FieldExpression) (degree : Nat → Nat)
    (certificate : DegreeCertificate program degree) (pub : Nat → Goldilocks)
    (rows : Nat → Goldilocks[X]) (bound : Nat)
    (rowBound : ∀ n, (rows n).natDegree ≤ bound) (node : Nat) :
    (polynomialAt program pub rows node).natDegree ≤ degree node * bound := by
  induction node using Nat.strong_induction_on with
  | h node ih =>
      rw [polynomialAt_eq]
      cases found : program[node]? with
      | none => simp
      | some expression =>
          have bounded : ∀ n,
              ((if n < node then polynomialAt program pub rows n else 0) :
                Goldilocks[X]).natDegree ≤ degree n * bound := by
            intro n
            split
            · exact ih n ‹n < node›
            · simp
          exact (expression_degree pub rows _ degree bound rowBound bounded expression).trans
            (Nat.mul_le_mul_right bound (certificate node expression found).1)

theorem polynomialAt_commutes (program : List FieldExpression) (degree : Nat → Nat)
    (certificate : DegreeCertificate program degree) (pub : Nat → Goldilocks)
    (rows : Nat → Goldilocks[X]) (bound : Nat)
    (rowBound : ∀ n, (rows n).natDegree ≤ bound) (node : Nat) (point : Goldilocks) :
    (polynomialAt program pub rows node).eval point =
      fieldAt program pub (fun n => (rows n).eval point) node := by
  induction node using Nat.strong_induction_on with
  | h node ih =>
      rw [polynomialAt_eq, fieldAt_eq]
      cases found : program[node]? with
      | none => simp
      | some expression =>
          have bounded : ∀ n,
              ((if n < node then polynomialAt program pub rows n else 0) :
                Goldilocks[X]).natDegree ≤ degree n * bound := by
            intro n
            split
            · exact polynomialAt_degree program degree certificate pub rows bound rowBound n
            · simp
          rw [expression_commutes pub rows _ degree bound bounded expression
            (certificate node expression found).2 point]
          congr 1
          funext n
          split
          · exact ih n ‹n < node›
          · simp


theorem normalize_cast (value : Nat) : (fieldNormalize value : Goldilocks) = (value : Goldilocks) := by
  exact ZMod.natCast_mod value fieldModulus

theorem sub_cast (left right : Nat) (bound : right ≤ left + fieldModulus) :
    (fieldSub left right : Goldilocks) = (left : Goldilocks) - (right : Goldilocks) := by
  change (((left + fieldModulus - right) % fieldModulus : Nat) : ZMod fieldModulus) = _
  simp only [ZMod.natCast_mod, Nat.cast_sub bound, Nat.cast_add, ZMod.natCast_self, add_zero]
  rfl

theorem normalize_bound (value : Nat) : fieldNormalize value < fieldModulus :=
  Nat.mod_lt _ (by decide)

/-- A successful instruction execution has the stated exact field meaning.
    The canonical-residue premise applies to its already-computed trace only. -/
theorem source_expression_refinement (pub rows values : List Nat)
    (canonical : ∀ n, values.getD n 0 < fieldModulus)
    (expression : FieldExpression) (value : Nat)
    (evaluated : evalFieldExpression pub rows values expression = some value) :
    value < fieldModulus ∧ (value : Goldilocks) =
      expressionField (fun n => (pub.getD n 0 : Goldilocks))
        (fun n => (rows.getD n 0 : Goldilocks))
        (fun n => (values.getD n 0 : Goldilocks)) expression := by
  have repr : ∀ n, ((values.getD n 0 : Nat) : Goldilocks).val = values.getD n 0 := by
    intro n
    exact Nat.mod_eq_of_lt (canonical n)
  have get : ∀ n v, values[n]? = some v → values.getD n 0 = v := by
    intro n v found
    simp [List.getD_eq_getElem?_getD, found]
  cases expression with
  | constant n =>
      simp only [evalFieldExpression, Option.some.injEq] at evaluated
      subst value
      exact ⟨normalize_bound n, normalize_cast n⟩
  | publicWord n =>
      cases found : pub[n]? with
      | none => simp [evalFieldExpression, found] at evaluated
      | some v =>
          simp [evalFieldExpression, found] at evaluated
          subst value
          exact ⟨normalize_bound v, by simp [expressionField, List.getD_eq_getElem?_getD,
            found, normalize_cast]⟩
  | witnessRow n =>
      cases found : rows[n]? with
      | none => simp [evalFieldExpression, found] at evaluated
      | some v =>
          simp [evalFieldExpression, found] at evaluated
          subst value
          exact ⟨normalize_bound v, by simp [expressionField, List.getD_eq_getElem?_getD,
            found, normalize_cast]⟩
  | add a b =>
      cases hx : values[a]? with
      | none => simp [evalFieldExpression, hx] at evaluated
      | some x =>
          cases hy : values[b]? with
          | none => simp [evalFieldExpression, hx, hy] at evaluated
          | some y =>
              simp [evalFieldExpression, hx, hy] at evaluated
              subst value
              exact ⟨normalize_bound _, by
                simp only [expressionField, get a x hx, get b y hy,
                  show (fieldAdd x y : Goldilocks) = (x : Goldilocks) + (y : Goldilocks) from
                    toGoldilocks_fieldAdd x y]⟩
  | mul a b =>
      cases hx : values[a]? with
      | none => simp [evalFieldExpression, hx] at evaluated
      | some x =>
          cases hy : values[b]? with
          | none => simp [evalFieldExpression, hx, hy] at evaluated
          | some y =>
              simp [evalFieldExpression, hx, hy] at evaluated
              subst value
              exact ⟨normalize_bound _, by
                simp only [expressionField, get a x hx, get b y hy,
                  show (fieldMul x y : Goldilocks) = (x : Goldilocks) * (y : Goldilocks) from
                    toGoldilocks_fieldMul x y]⟩
  | sub a b =>
      cases hx : values[a]? with
      | none => simp [evalFieldExpression, hx] at evaluated
      | some x =>
          cases hy : values[b]? with
          | none => simp [evalFieldExpression, hx, hy] at evaluated
          | some y =>
              simp [evalFieldExpression, hx, hy] at evaluated
              subst value
              have bound := canonical b
              rw [get b y hy] at bound
              exact ⟨normalize_bound _, by
                simp only [expressionField, get a x hx, get b y hy, sub_cast x y (by omega)]⟩
  | neg a =>
      cases hx : values[a]? with
      | none => simp [evalFieldExpression, hx] at evaluated
      | some x =>
          simp [evalFieldExpression, hx] at evaluated
          subst value
          have bound := canonical a
          rw [get a x hx] at bound
          exact ⟨normalize_bound _, by
            simp only [expressionField, get a x hx, sub_cast 0 x (by omega), Nat.cast_zero, zero_sub]⟩
  | inverse a =>
      cases hx : values[a]? with
      | none => simp [evalFieldExpression, hx] at evaluated
      | some x =>
          simp [evalFieldExpression, hx] at evaluated
          subst value
          constructor
          · unfold fieldInverse
            split
            · decide
            · exact normalize_bound _
          · have rx : (x : Goldilocks).val = x := by
              simpa only [get a x hx] using repr a
            simp only [expressionField, get a x hx, rx]
  | bit a b =>
      cases hx : values[a]? with
      | none => simp [evalFieldExpression, hx] at evaluated
      | some x =>
          simp [evalFieldExpression, hx] at evaluated
          subst value
          have rx : (x : Goldilocks).val = x := by
            simpa only [get a x hx] using repr a
          exact ⟨(Nat.mod_lt _ (by decide : 0 < 2)).trans (by decide), by
            simp only [expressionField, get a x hx, rx]⟩
  | selectEqual a b c d =>
      cases hx : values[a]? with
      | none => simp [evalFieldExpression, hx] at evaluated
      | some x =>
          cases hy : values[b]? with
          | none => simp [evalFieldExpression, hx, hy] at evaluated
          | some y =>
              have selected := evaluated
              simp [evalFieldExpression, hx, hy] at selected
              have same : ((x : Goldilocks) = (y : Goldilocks)) ↔ x = y := by
                constructor
                · intro equal
                  have h := congrArg (fun v : Goldilocks => v.val) equal
                  have rx := repr a
                  have ry := repr b
                  rw [get a x hx] at rx
                  rw [get b y hy] at ry
                  simpa [rx, ry] using h
                · intro equal
                  rw [equal]
              by_cases equal : x = y
              · simp only [equal, if_true] at selected
                have hc := get c value selected
                exact ⟨by rw [← hc]; exact canonical c, by
                  simp only [expressionField, get a x hx, get b y hy, same, if_pos equal, hc]⟩
              · simp only [equal, if_false] at selected
                have hd := get d value selected
                exact ⟨by rw [← hd]; exact canonical d, by
                  simp only [expressionField, get a x hx, get b y hy, same, if_neg equal, hd]⟩

theorem canonical_getD (values : List Nat)
    (canonical : ∀ value, value ∈ values → value < fieldModulus) (node : Nat) :
    values.getD node 0 < fieldModulus := by
  cases found : values[node]? with
  | none => simp [List.getD_eq_getElem?_getD, found, fieldModulus]
  | some value =>
      simpa [List.getD_eq_getElem?_getD, found] using
        canonical value (List.mem_of_getElem? found)

theorem source_go_canonical (pub rows initial result : List Nat)
    (program : List FieldExpression)
    (canonical : ∀ value, value ∈ initial → value < fieldModulus)
    (evaluated : evalExpressionNodes.go pub rows program initial = some result) :
    ∀ value, value ∈ result → value < fieldModulus := by
  induction program generalizing initial with
  | nil =>
      simp only [evalExpressionNodes.go, Option.some.injEq] at evaluated
      simpa [← evaluated] using canonical
  | cons expression tail ih =>
      cases computed : evalFieldExpression pub rows initial expression with
      | none => simp [evalExpressionNodes.go, computed] at evaluated
      | some value =>
          simp only [evalExpressionNodes.go, computed] at evaluated
          apply ih (initial ++ [value]) _ evaluated
          intro next member
          simp only [List.mem_append, List.mem_singleton] at member
          rcases member with old | new
          · exact canonical next old
          · subst next
            exact (source_expression_refinement pub rows initial
              (canonical_getD initial canonical) expression value computed).1

theorem expressionField_congr_prior (pub rows left right : Nat → Goldilocks)
    (node : Nat) (expression : FieldExpression)
    (canonical : expression.CanonicalAt true node)
    (same : ∀ i, i < node → left i = right i) :
    expressionField pub rows left expression = expressionField pub rows right expression := by
  cases expression <;> simp only [FieldExpression.CanonicalAt] at canonical
  all_goals simp_all [expressionField]

/-- Exact source-interpreter refinement, obtained from actual successful evaluation
    and graph canonicality; the desired field-evaluator equality is a conclusion. -/
theorem fieldAt_refines_source (program : ExpressionProgram) (pub rows values : List Nat)
    (canonical : program.Canonical true)
    (evaluated : evalExpressionNodes pub rows program.expressions = some values)
    (node : Nat) (inBounds : node < program.expressions.length) :
    fieldAt program.expressions (fun n => (pub.getD n 0 : Goldilocks))
      (fun n => (rows.getD n 0 : Goldilocks)) node = (values.getD node 0 : Goldilocks) := by
  have allCanonical := source_go_canonical pub rows [] values program.expressions
    (by simp) evaluated
  obtain ⟨suffix, resultEq, suffixLength, equations⟩ :=
    V8Smz9SemanticBinding.eval_go_equations pub rows [] values program.expressions
      (by simpa using canonical.1) evaluated
  have lengthEq : values.length = program.expressions.length := by
    simpa [resultEq] using suffixLength
  induction node using Nat.strong_induction_on with
  | h node ih =>
      have valueBounds : node < values.length := by omega
      have expressionFound := List.getElem?_eq_getElem inBounds
      have valueFound := List.getElem?_eq_getElem valueBounds
      have computed : evalFieldExpression pub rows values program.expressions[node] =
          some values[node] := by
        rw [← V8Smz9SemanticBinding.evaluated_program_satisfies_each_node
          canonical evaluated expressionFound]
        exact valueFound
      have source := (source_expression_refinement pub rows values
        (canonical_getD values allCanonical) program.expressions[node] values[node] computed).2
      rw [fieldAt_eq, expressionFound]
      dsimp only
      have same := expressionField_congr_prior
        (fun n => (pub.getD n 0 : Goldilocks)) (fun n => (rows.getD n 0 : Goldilocks))
        (fun n => if n < node then fieldAt program.expressions
          (fun n => (pub.getD n 0 : Goldilocks)) (fun n => (rows.getD n 0 : Goldilocks)) n else 0)
        (fun n => (values.getD n 0 : Goldilocks)) node program.expressions[node]
        (canonical.1 node _ expressionFound) (by
          intro i before
          rw [if_pos before]
          exact ih i before (by omega))
      rw [same, ← source]
      simp [List.getD_eq_getElem?_getD, valueFound]

/-- Checked certificate data; the parser that generated this array is not trusted. -/
def exactFormalDegreeBlocks : List (List Nat) := [
  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2],
  [1, 2, 1, 2, 1, 2, 1, 2, 1, 0, 1, 1, 1, 2, 1, 1, 3, 1, 1, 4, 4, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 1, 1, 1, 2, 1, 1, 3, 1, 1, 4, 4, 1, 1, 1, 1, 2, 1, 1, 3, 1, 1, 4, 4, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 3, 1, 1, 4, 4],
  [0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 3, 1, 4, 2, 3, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 1, 4, 4, 2, 3, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 1, 4, 4, 2, 3, 3, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 1, 4, 4, 4, 4, 4],
  [4, 4, 4, 4, 4, 0, 0, 4, 4, 4, 4, 4, 4, 4, 4, 0, 4, 4, 4, 4, 4, 4, 4, 4, 0, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 2, 2, 1, 2, 1, 1, 2, 1, 2, 1, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
  [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2],
  [2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 2, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3],
  [1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 2, 2, 1, 2, 3, 2, 1, 3, 1, 2, 3, 2, 1, 1, 1, 1, 1, 3, 1, 2, 3, 2, 1, 1, 1, 1, 3, 1, 2, 3, 2, 1, 1, 1, 3, 1, 2, 3, 2, 1, 1, 3, 1, 2, 3, 2, 1, 3, 1, 1, 1, 1, 1, 1, 2, 1, 2, 3, 2, 3, 1, 2],
  [3, 2, 3, 1, 2, 3, 2, 3, 1, 2, 3, 2, 3, 1, 2, 3, 2, 3, 1, 2, 3, 2, 3, 1, 1, 1, 1, 1, 1, 2, 2, 3, 1, 1, 2, 2, 3, 1, 1, 2, 2, 3, 1, 1, 2, 2, 3, 1, 1, 2, 2, 3, 1, 1, 2, 2, 3, 1, 1, 2, 2, 2, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1, 2, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 3, 1, 3, 1, 3, 1, 3, 1],
  [3, 1, 3, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 2, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2],
  [2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 1, 3, 2, 2, 5, 2, 3, 4, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 2, 4, 6],
  [7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6],
  [7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1],
  [0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1],
  [0, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1],
  [1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1],
  [0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4],
  [6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1],
  [0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7],
  [1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 0, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7],
  [1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
  [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4],
  [6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 7],
  [7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2],
  [4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4],
  [6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4],
  [6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2],
  [4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1],
  [2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1],
  [7, 7, 1, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7],
  [1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7],
  [1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 7, 7, 1, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 1, 2, 4, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7],
  [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 1, 2, 1, 3, 1, 4, 1, 5, 1, 6, 1, 7, 0, 2, 0, 0, 3, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0, 0, 6, 7, 2, 0, 3, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0, 0, 6, 7, 7, 0, 0, 3, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0, 0, 6, 7],
  [7, 0, 0, 0, 0, 4, 0, 0, 5, 0, 0, 6, 0, 0, 0, 6, 7, 7, 0, 0, 0, 0, 0, 0, 5, 0, 0, 6, 0, 0, 0, 6, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 6, 7, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 7, 7, 8, 8, 1, 2, 2, 2, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3],
  [4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4, 1, 1, 1, 2, 3, 4]
]

def exactDegree (node : Nat) : Nat :=
  (exactFormalDegreeBlocks.getD (node / 128) []).getD (node % 128) 0

theorem exact_degree_certificate : DegreeCertificate exactNonlinearExpressions exactDegree := by
  have checked : checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 0 exactNonlinearExpressions = true := by
    decide
  simpa [DegreeCertificate, checkIndexed_eq_true] using checked

theorem exact_root_degree_le : ∀ root, root ∈ exactNonlinearRoots → exactDegree root ≤ 8 := by
  have checked : exactNonlinearRoots.all (fun root => decide (exactDegree root ≤ 8)) = true := by
    decide
  simpa using checked

def constraintPolynomials (pub : Nat → Goldilocks) (rows : Nat → Goldilocks[X])
    (constraint : Fin 830) : Goldilocks[X] :=
  polynomialAt exactNonlinearExpressions pub rows (exactNonlinearRoots.getD constraint.val 0)

def constraintOpenings (pub rows : Nat → Goldilocks) (constraint : Fin 830) : Goldilocks :=
  fieldAt exactNonlinearExpressions pub rows (exactNonlinearRoots.getD constraint.val 0)

theorem constraint_polynomials_commute (pub : Nat → Goldilocks) (rows : Nat → Goldilocks[X])
    (rowBound : ∀ n, (rows n).natDegree ≤ 69) (constraint : Fin 830) (point : Goldilocks) :
    (constraintPolynomials pub rows constraint).eval point =
      constraintOpenings pub (fun n => (rows n).eval point) constraint :=
  polynomialAt_commutes exactNonlinearExpressions exactDegree exact_degree_certificate
    pub rows 69 rowBound _ point

theorem exact_root_count : exactNonlinearRoots.length = 830 := by decide

theorem constraint_polynomials_degree_le (pub : Nat → Goldilocks)
    (rows : Nat → Goldilocks[X]) (rowBound : ∀ n, (rows n).natDegree ≤ 69)
    (constraint : Fin 830) : (constraintPolynomials pub rows constraint).natDegree ≤ 552 := by
  have rootBound : constraint.val < exactNonlinearRoots.length := by
    rw [exact_root_count]
    exact constraint.isLt
  have member : exactNonlinearRoots.getD constraint.val 0 ∈ exactNonlinearRoots := by
    simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem rootBound]
  exact (polynomialAt_degree exactNonlinearExpressions exactDegree exact_degree_certificate
    pub rows 69 rowBound _).trans
    ((Nat.mul_le_mul_right 69 (exact_root_degree_le _ member)).trans (by decide))

theorem constraint_root_member (constraint : Fin 830) :
    exactNonlinearRoots.getD constraint.val 0 ∈ exactNonlinearRoots := by
  have bound : constraint.val < exactNonlinearRoots.length := by
    rw [exact_root_count]
    exact constraint.isLt
  simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem bound]

theorem constraint_polynomial_refines_source (pub rows values : List Nat)
    (rowPolynomials : Nat → Goldilocks[X])
    (rowBound : ∀ n, (rowPolynomials n).natDegree ≤ 69)
    (point : Goldilocks)
    (rowOpenings : ∀ n, (rowPolynomials n).eval point = (rows.getD n 0 : Goldilocks))
    (evaluated : evalExpressionNodes pub rows exactNonlinearExpressions = some values)
    (constraint : Fin 830) :
    (constraintPolynomials (fun n => (pub.getD n 0 : Goldilocks))
      rowPolynomials constraint).eval point =
      (values.getD (exactNonlinearRoots.getD constraint.val 0) 0 : Goldilocks) := by
  rw [constraint_polynomials_commute _ _ rowBound, funext rowOpenings]
  exact fieldAt_refines_source hgv8rp03ProgramComponents.nonlinearExecutable pub rows values
    hgv8rp03_nonlinear_expression_program_is_canonical evaluated _
    (hgv8rp03_nonlinear_expression_program_is_canonical.2 _ (constraint_root_member constraint))

/-- Every accepted source packing assignment makes all 830 actual polynomial
    constraints vanish, for any row polynomials opening to that assignment. -/
theorem accepted_source_constraints_vanish (pub rows : List Nat)
    (rowPolynomials : Nat → Goldilocks[X])
    (rowBound : ∀ n, (rowPolynomials n).natDegree ≤ 69)
    (point : Goldilocks)
    (rowOpenings : ∀ n, (rowPolynomials n).eval point = (rows.getD n 0 : Goldilocks))
    (accepted : hgv8rp03ProgramComponents.nonlinearExecutable.Accepts pub rows)
    (constraint : Fin 830) :
    (constraintPolynomials (fun n => (pub.getD n 0 : Goldilocks))
      rowPolynomials constraint).eval point = 0 := by
  obtain ⟨values, evaluated, zero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero accepted
      (constraint_root_member constraint)
  rw [constraint_polynomial_refines_source pub rows values rowPolynomials rowBound point
    rowOpenings evaluated constraint]
  change (values[exactNonlinearRoots.getD constraint.val 0]?.getD 0 : Goldilocks) = 0
  rw [zero]
  rfl

end
end HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
