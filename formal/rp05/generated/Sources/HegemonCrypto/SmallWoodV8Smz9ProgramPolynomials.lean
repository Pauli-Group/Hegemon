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

private theorem checkIndexed_append {α : Type} (predicate : Nat → α → Bool)
    (left right : List α) (start : Nat) :
    checkIndexed predicate start (left ++ right) =
      (checkIndexed predicate start left &&
        checkIndexed predicate (start + left.length) right) := by
  induction left generalizing start with
  | nil => simp [checkIndexed]
  | cons head rest ih =>
      simp [checkIndexed, ih, Nat.add_comm, Nat.add_left_comm,
        Bool.and_assoc]

private theorem checkIndexed_flatten_cons {α : Type} (predicate : Nat → α → Bool)
    (head : List α) (rest : List (List α)) (start : Nat)
    (headChecked : checkIndexed predicate start head = true)
    (restChecked : checkIndexed predicate (start + head.length) rest.flatten = true) :
    checkIndexed predicate start (head :: rest).flatten = true := by
  change checkIndexed predicate start (head ++ rest.flatten) = true
  rw [checkIndexed_append, headChecked, restChecked]
  rfl

private theorem degreeCertificate_of_checkIndexed (program : List FieldExpression)
    (degree : Nat → Nat)
    (checked : checkIndexed (fun node expression => decide
      (expressionDegree degree expression ≤ degree node ∧
        expressionSafe degree expression)) 0 program = true) :
    DegreeCertificate program degree := by
  intro node expression found
  have valid := (checkIndexed_eq_true (fun node expression => decide
    (expressionDegree degree expression ≤ degree node ∧
      expressionSafe degree expression)) program 0).mp checked node expression found
  simpa only [Nat.zero_add, decide_eq_true_eq] using valid

private theorem exact_degree_chunk_000 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 0
      ([FieldExpression.constant 0, FieldExpression.constant 1, FieldExpression.constant 2, FieldExpression.constant 18446744069414584320, FieldExpression.publicWord 0, FieldExpression.publicWord 1, FieldExpression.publicWord 2, FieldExpression.publicWord 3, FieldExpression.publicWord 4, FieldExpression.publicWord 5, FieldExpression.publicWord 6, FieldExpression.publicWord 7, FieldExpression.publicWord 8, FieldExpression.publicWord 9, FieldExpression.publicWord 10, FieldExpression.publicWord 11, FieldExpression.publicWord 12, FieldExpression.publicWord 13, FieldExpression.publicWord 14, FieldExpression.publicWord 15, FieldExpression.publicWord 16, FieldExpression.publicWord 17, FieldExpression.publicWord 18, FieldExpression.publicWord 19, FieldExpression.publicWord 20, FieldExpression.publicWord 21, FieldExpression.publicWord 22, FieldExpression.publicWord 23, FieldExpression.publicWord 24, FieldExpression.publicWord 25, FieldExpression.publicWord 26, FieldExpression.publicWord 27] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_001 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 32
      ([FieldExpression.publicWord 28, FieldExpression.publicWord 29, FieldExpression.publicWord 30, FieldExpression.publicWord 31, FieldExpression.publicWord 32, FieldExpression.publicWord 33, FieldExpression.publicWord 34, FieldExpression.publicWord 35, FieldExpression.publicWord 36, FieldExpression.publicWord 37, FieldExpression.publicWord 38, FieldExpression.publicWord 39, FieldExpression.publicWord 40, FieldExpression.publicWord 41, FieldExpression.publicWord 42, FieldExpression.publicWord 43, FieldExpression.publicWord 44, FieldExpression.publicWord 45, FieldExpression.publicWord 46, FieldExpression.publicWord 47, FieldExpression.publicWord 48, FieldExpression.publicWord 49, FieldExpression.publicWord 50, FieldExpression.publicWord 51, FieldExpression.publicWord 52, FieldExpression.publicWord 53, FieldExpression.publicWord 54, FieldExpression.publicWord 55, FieldExpression.publicWord 56, FieldExpression.publicWord 57, FieldExpression.publicWord 58, FieldExpression.publicWord 59] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_002 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 64
      ([FieldExpression.publicWord 60, FieldExpression.publicWord 61, FieldExpression.publicWord 62, FieldExpression.publicWord 63, FieldExpression.publicWord 64, FieldExpression.publicWord 65, FieldExpression.publicWord 66, FieldExpression.publicWord 67, FieldExpression.publicWord 68, FieldExpression.publicWord 69, FieldExpression.publicWord 70, FieldExpression.publicWord 71, FieldExpression.publicWord 72, FieldExpression.publicWord 73, FieldExpression.publicWord 74, FieldExpression.publicWord 75, FieldExpression.publicWord 76, FieldExpression.publicWord 77, FieldExpression.publicWord 78, FieldExpression.publicWord 79, FieldExpression.publicWord 80, FieldExpression.publicWord 81, FieldExpression.publicWord 82, FieldExpression.publicWord 83, FieldExpression.publicWord 84, FieldExpression.publicWord 85, FieldExpression.publicWord 86, FieldExpression.publicWord 87, FieldExpression.publicWord 88, FieldExpression.publicWord 89, FieldExpression.publicWord 90, FieldExpression.publicWord 91] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_003 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 96
      ([FieldExpression.publicWord 92, FieldExpression.publicWord 93, FieldExpression.publicWord 94, FieldExpression.publicWord 95, FieldExpression.publicWord 96, FieldExpression.publicWord 97, FieldExpression.publicWord 98, FieldExpression.publicWord 99, FieldExpression.publicWord 100, FieldExpression.publicWord 101, FieldExpression.publicWord 102, FieldExpression.publicWord 103, FieldExpression.publicWord 104, FieldExpression.publicWord 105, FieldExpression.publicWord 106, FieldExpression.publicWord 107, FieldExpression.publicWord 108, FieldExpression.publicWord 109, FieldExpression.publicWord 110, FieldExpression.publicWord 111, FieldExpression.publicWord 112, FieldExpression.publicWord 113, FieldExpression.publicWord 114, FieldExpression.publicWord 115, FieldExpression.publicWord 116, FieldExpression.publicWord 117, FieldExpression.publicWord 118, FieldExpression.publicWord 119, FieldExpression.witnessRow 0, FieldExpression.witnessRow 1, FieldExpression.witnessRow 2, FieldExpression.witnessRow 3] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_004 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 128
      ([FieldExpression.witnessRow 4, FieldExpression.witnessRow 5, FieldExpression.witnessRow 6, FieldExpression.witnessRow 7, FieldExpression.witnessRow 8, FieldExpression.witnessRow 9, FieldExpression.witnessRow 10, FieldExpression.witnessRow 11, FieldExpression.witnessRow 12, FieldExpression.witnessRow 13, FieldExpression.witnessRow 14, FieldExpression.witnessRow 15, FieldExpression.witnessRow 16, FieldExpression.witnessRow 17, FieldExpression.witnessRow 18, FieldExpression.witnessRow 19, FieldExpression.witnessRow 20, FieldExpression.witnessRow 21, FieldExpression.witnessRow 22, FieldExpression.witnessRow 23, FieldExpression.witnessRow 24, FieldExpression.witnessRow 25, FieldExpression.witnessRow 26, FieldExpression.witnessRow 27, FieldExpression.witnessRow 28, FieldExpression.witnessRow 29, FieldExpression.witnessRow 30, FieldExpression.witnessRow 31, FieldExpression.witnessRow 32, FieldExpression.witnessRow 33, FieldExpression.witnessRow 34, FieldExpression.witnessRow 35] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_005 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 160
      ([FieldExpression.witnessRow 36, FieldExpression.witnessRow 37, FieldExpression.witnessRow 38, FieldExpression.witnessRow 39, FieldExpression.witnessRow 40, FieldExpression.witnessRow 41, FieldExpression.witnessRow 42, FieldExpression.witnessRow 43, FieldExpression.witnessRow 44, FieldExpression.witnessRow 45, FieldExpression.witnessRow 46, FieldExpression.witnessRow 47, FieldExpression.witnessRow 48, FieldExpression.witnessRow 49, FieldExpression.witnessRow 50, FieldExpression.witnessRow 51, FieldExpression.witnessRow 52, FieldExpression.witnessRow 53, FieldExpression.witnessRow 54, FieldExpression.witnessRow 55, FieldExpression.witnessRow 56, FieldExpression.witnessRow 57, FieldExpression.witnessRow 58, FieldExpression.witnessRow 59, FieldExpression.witnessRow 60, FieldExpression.witnessRow 61, FieldExpression.witnessRow 62, FieldExpression.witnessRow 63, FieldExpression.witnessRow 64, FieldExpression.witnessRow 65, FieldExpression.witnessRow 66, FieldExpression.witnessRow 67] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_006 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 192
      ([FieldExpression.witnessRow 68, FieldExpression.witnessRow 69, FieldExpression.witnessRow 70, FieldExpression.witnessRow 71, FieldExpression.witnessRow 72, FieldExpression.witnessRow 73, FieldExpression.witnessRow 74, FieldExpression.witnessRow 75, FieldExpression.witnessRow 76, FieldExpression.witnessRow 77, FieldExpression.witnessRow 78, FieldExpression.witnessRow 79, FieldExpression.witnessRow 80, FieldExpression.witnessRow 81, FieldExpression.witnessRow 82, FieldExpression.witnessRow 83, FieldExpression.witnessRow 84, FieldExpression.witnessRow 85, FieldExpression.witnessRow 86, FieldExpression.witnessRow 87, FieldExpression.witnessRow 88, FieldExpression.witnessRow 89, FieldExpression.witnessRow 90, FieldExpression.witnessRow 91, FieldExpression.witnessRow 92, FieldExpression.witnessRow 93, FieldExpression.witnessRow 94, FieldExpression.witnessRow 95, FieldExpression.witnessRow 96, FieldExpression.witnessRow 97, FieldExpression.witnessRow 98, FieldExpression.witnessRow 99] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_007 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 224
      ([FieldExpression.witnessRow 100, FieldExpression.witnessRow 101, FieldExpression.witnessRow 102, FieldExpression.witnessRow 103, FieldExpression.witnessRow 104, FieldExpression.witnessRow 105, FieldExpression.witnessRow 106, FieldExpression.witnessRow 107, FieldExpression.witnessRow 108, FieldExpression.witnessRow 109, FieldExpression.witnessRow 110, FieldExpression.witnessRow 111, FieldExpression.witnessRow 112, FieldExpression.witnessRow 113, FieldExpression.witnessRow 114, FieldExpression.witnessRow 115, FieldExpression.witnessRow 116, FieldExpression.witnessRow 117, FieldExpression.witnessRow 118, FieldExpression.witnessRow 119, FieldExpression.witnessRow 120, FieldExpression.witnessRow 121, FieldExpression.witnessRow 122, FieldExpression.witnessRow 123, FieldExpression.witnessRow 124, FieldExpression.witnessRow 125, FieldExpression.witnessRow 126, FieldExpression.witnessRow 127, FieldExpression.witnessRow 128, FieldExpression.witnessRow 129, FieldExpression.witnessRow 130, FieldExpression.witnessRow 131] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_008 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 256
      ([FieldExpression.witnessRow 132, FieldExpression.witnessRow 133, FieldExpression.witnessRow 134, FieldExpression.witnessRow 135, FieldExpression.witnessRow 136, FieldExpression.witnessRow 137, FieldExpression.witnessRow 138, FieldExpression.witnessRow 139, FieldExpression.witnessRow 140, FieldExpression.witnessRow 141, FieldExpression.witnessRow 142, FieldExpression.witnessRow 143, FieldExpression.witnessRow 144, FieldExpression.witnessRow 145, FieldExpression.witnessRow 146, FieldExpression.witnessRow 147, FieldExpression.witnessRow 148, FieldExpression.witnessRow 149, FieldExpression.witnessRow 150, FieldExpression.witnessRow 151, FieldExpression.witnessRow 152, FieldExpression.witnessRow 153, FieldExpression.witnessRow 154, FieldExpression.witnessRow 155, FieldExpression.witnessRow 156, FieldExpression.witnessRow 157, FieldExpression.witnessRow 158, FieldExpression.witnessRow 159, FieldExpression.witnessRow 160, FieldExpression.witnessRow 161, FieldExpression.witnessRow 162, FieldExpression.witnessRow 163] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_009 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 288
      ([FieldExpression.witnessRow 164, FieldExpression.witnessRow 165, FieldExpression.witnessRow 166, FieldExpression.witnessRow 167, FieldExpression.witnessRow 168, FieldExpression.witnessRow 169, FieldExpression.witnessRow 170, FieldExpression.witnessRow 171, FieldExpression.witnessRow 172, FieldExpression.witnessRow 173, FieldExpression.witnessRow 174, FieldExpression.witnessRow 175, FieldExpression.witnessRow 176, FieldExpression.witnessRow 177, FieldExpression.witnessRow 178, FieldExpression.witnessRow 179, FieldExpression.witnessRow 180, FieldExpression.witnessRow 181, FieldExpression.witnessRow 182, FieldExpression.witnessRow 183, FieldExpression.witnessRow 184, FieldExpression.witnessRow 185, FieldExpression.witnessRow 186, FieldExpression.witnessRow 187, FieldExpression.witnessRow 188, FieldExpression.witnessRow 189, FieldExpression.witnessRow 190, FieldExpression.witnessRow 191, FieldExpression.witnessRow 192, FieldExpression.witnessRow 193, FieldExpression.witnessRow 194, FieldExpression.witnessRow 195] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_010 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 320
      ([FieldExpression.witnessRow 196, FieldExpression.witnessRow 197, FieldExpression.witnessRow 198, FieldExpression.witnessRow 199, FieldExpression.witnessRow 200, FieldExpression.witnessRow 201, FieldExpression.witnessRow 202, FieldExpression.witnessRow 203, FieldExpression.witnessRow 204, FieldExpression.witnessRow 205, FieldExpression.witnessRow 206, FieldExpression.witnessRow 207, FieldExpression.witnessRow 208, FieldExpression.witnessRow 209, FieldExpression.witnessRow 210, FieldExpression.witnessRow 211, FieldExpression.witnessRow 212, FieldExpression.witnessRow 213, FieldExpression.witnessRow 214, FieldExpression.witnessRow 215, FieldExpression.witnessRow 216, FieldExpression.witnessRow 217, FieldExpression.witnessRow 218, FieldExpression.witnessRow 219, FieldExpression.witnessRow 220, FieldExpression.witnessRow 221, FieldExpression.witnessRow 222, FieldExpression.witnessRow 223, FieldExpression.witnessRow 224, FieldExpression.witnessRow 225, FieldExpression.witnessRow 226, FieldExpression.witnessRow 227] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_011 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 352
      ([FieldExpression.witnessRow 228, FieldExpression.witnessRow 229, FieldExpression.witnessRow 230, FieldExpression.witnessRow 231, FieldExpression.witnessRow 232, FieldExpression.witnessRow 233, FieldExpression.witnessRow 234, FieldExpression.witnessRow 235, FieldExpression.witnessRow 236, FieldExpression.witnessRow 237, FieldExpression.witnessRow 238, FieldExpression.witnessRow 239, FieldExpression.witnessRow 240, FieldExpression.witnessRow 241, FieldExpression.witnessRow 242, FieldExpression.witnessRow 243, FieldExpression.witnessRow 244, FieldExpression.witnessRow 245, FieldExpression.witnessRow 246, FieldExpression.witnessRow 247, FieldExpression.witnessRow 248, FieldExpression.witnessRow 249, FieldExpression.witnessRow 250, FieldExpression.witnessRow 251, FieldExpression.witnessRow 252, FieldExpression.witnessRow 253, FieldExpression.witnessRow 254, FieldExpression.witnessRow 255, FieldExpression.witnessRow 256, FieldExpression.witnessRow 257, FieldExpression.witnessRow 258, FieldExpression.witnessRow 259] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_012 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 384
      ([FieldExpression.witnessRow 260, FieldExpression.witnessRow 261, FieldExpression.witnessRow 262, FieldExpression.witnessRow 263, FieldExpression.witnessRow 264, FieldExpression.witnessRow 265, FieldExpression.witnessRow 266, FieldExpression.witnessRow 267, FieldExpression.witnessRow 268, FieldExpression.witnessRow 269, FieldExpression.witnessRow 270, FieldExpression.witnessRow 271, FieldExpression.witnessRow 272, FieldExpression.witnessRow 273, FieldExpression.witnessRow 274, FieldExpression.witnessRow 275, FieldExpression.witnessRow 276, FieldExpression.witnessRow 277, FieldExpression.witnessRow 278, FieldExpression.witnessRow 279, FieldExpression.witnessRow 280, FieldExpression.witnessRow 281, FieldExpression.witnessRow 282, FieldExpression.witnessRow 283, FieldExpression.witnessRow 284, FieldExpression.witnessRow 285, FieldExpression.witnessRow 286, FieldExpression.witnessRow 287, FieldExpression.witnessRow 288, FieldExpression.witnessRow 289, FieldExpression.witnessRow 290, FieldExpression.witnessRow 291] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_013 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 416
      ([FieldExpression.witnessRow 292, FieldExpression.witnessRow 293, FieldExpression.witnessRow 294, FieldExpression.witnessRow 295, FieldExpression.witnessRow 296, FieldExpression.witnessRow 297, FieldExpression.witnessRow 298, FieldExpression.witnessRow 299, FieldExpression.witnessRow 300, FieldExpression.witnessRow 301, FieldExpression.witnessRow 302, FieldExpression.witnessRow 303, FieldExpression.witnessRow 304, FieldExpression.witnessRow 305, FieldExpression.witnessRow 306, FieldExpression.witnessRow 307, FieldExpression.witnessRow 308, FieldExpression.witnessRow 309, FieldExpression.witnessRow 310, FieldExpression.witnessRow 311, FieldExpression.witnessRow 312, FieldExpression.witnessRow 313, FieldExpression.witnessRow 314, FieldExpression.witnessRow 315, FieldExpression.witnessRow 316, FieldExpression.witnessRow 317, FieldExpression.witnessRow 318, FieldExpression.witnessRow 319, FieldExpression.witnessRow 320, FieldExpression.witnessRow 321, FieldExpression.witnessRow 322, FieldExpression.witnessRow 323] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_014 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 448
      ([FieldExpression.witnessRow 324, FieldExpression.witnessRow 325, FieldExpression.witnessRow 326, FieldExpression.witnessRow 327, FieldExpression.witnessRow 328, FieldExpression.witnessRow 329, FieldExpression.witnessRow 330, FieldExpression.witnessRow 331, FieldExpression.witnessRow 332, FieldExpression.witnessRow 333, FieldExpression.witnessRow 334, FieldExpression.witnessRow 335, FieldExpression.witnessRow 336, FieldExpression.witnessRow 337, FieldExpression.witnessRow 338, FieldExpression.witnessRow 339, FieldExpression.witnessRow 340, FieldExpression.witnessRow 341, FieldExpression.witnessRow 342, FieldExpression.witnessRow 343, FieldExpression.witnessRow 344, FieldExpression.witnessRow 345, FieldExpression.witnessRow 346, FieldExpression.witnessRow 347, FieldExpression.witnessRow 348, FieldExpression.witnessRow 349, FieldExpression.witnessRow 350, FieldExpression.witnessRow 351, FieldExpression.witnessRow 352, FieldExpression.witnessRow 353, FieldExpression.witnessRow 354, FieldExpression.witnessRow 355] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_015 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 480
      ([FieldExpression.witnessRow 356, FieldExpression.witnessRow 357, FieldExpression.witnessRow 358, FieldExpression.witnessRow 359, FieldExpression.witnessRow 360, FieldExpression.witnessRow 361, FieldExpression.witnessRow 362, FieldExpression.witnessRow 363, FieldExpression.witnessRow 364, FieldExpression.witnessRow 365, FieldExpression.witnessRow 366, FieldExpression.witnessRow 367, FieldExpression.witnessRow 368, FieldExpression.witnessRow 369, FieldExpression.witnessRow 370, FieldExpression.witnessRow 371, FieldExpression.witnessRow 372, FieldExpression.witnessRow 373, FieldExpression.witnessRow 374, FieldExpression.witnessRow 375, FieldExpression.witnessRow 376, FieldExpression.witnessRow 377, FieldExpression.witnessRow 378, FieldExpression.witnessRow 379, FieldExpression.witnessRow 380, FieldExpression.witnessRow 381, FieldExpression.witnessRow 382, FieldExpression.witnessRow 383, FieldExpression.witnessRow 384, FieldExpression.witnessRow 385, FieldExpression.witnessRow 386, FieldExpression.witnessRow 387] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_016 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 512
      ([FieldExpression.witnessRow 388, FieldExpression.witnessRow 389, FieldExpression.witnessRow 390, FieldExpression.witnessRow 391, FieldExpression.witnessRow 392, FieldExpression.witnessRow 393, FieldExpression.witnessRow 394, FieldExpression.witnessRow 395, FieldExpression.witnessRow 396, FieldExpression.witnessRow 397, FieldExpression.witnessRow 398, FieldExpression.witnessRow 399, FieldExpression.witnessRow 400, FieldExpression.witnessRow 401, FieldExpression.witnessRow 402, FieldExpression.witnessRow 403, FieldExpression.witnessRow 404, FieldExpression.witnessRow 405, FieldExpression.witnessRow 406, FieldExpression.witnessRow 407, FieldExpression.witnessRow 408, FieldExpression.witnessRow 409, FieldExpression.witnessRow 410, FieldExpression.witnessRow 411, FieldExpression.witnessRow 412, FieldExpression.witnessRow 413, FieldExpression.witnessRow 414, FieldExpression.witnessRow 415, FieldExpression.witnessRow 416, FieldExpression.witnessRow 417, FieldExpression.witnessRow 418, FieldExpression.witnessRow 419] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_017 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 544
      ([FieldExpression.witnessRow 420, FieldExpression.witnessRow 421, FieldExpression.witnessRow 422, FieldExpression.witnessRow 423, FieldExpression.witnessRow 424, FieldExpression.witnessRow 425, FieldExpression.witnessRow 426, FieldExpression.witnessRow 427, FieldExpression.witnessRow 428, FieldExpression.witnessRow 429, FieldExpression.witnessRow 430, FieldExpression.witnessRow 431, FieldExpression.witnessRow 432, FieldExpression.witnessRow 433, FieldExpression.witnessRow 434, FieldExpression.witnessRow 435, FieldExpression.witnessRow 436, FieldExpression.witnessRow 437, FieldExpression.witnessRow 438, FieldExpression.witnessRow 439, FieldExpression.witnessRow 440, FieldExpression.witnessRow 441, FieldExpression.witnessRow 442, FieldExpression.witnessRow 443, FieldExpression.witnessRow 444, FieldExpression.witnessRow 445, FieldExpression.witnessRow 446, FieldExpression.witnessRow 447, FieldExpression.witnessRow 448, FieldExpression.witnessRow 449, FieldExpression.witnessRow 450, FieldExpression.witnessRow 451] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_018 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 576
      ([FieldExpression.witnessRow 452, FieldExpression.witnessRow 453, FieldExpression.witnessRow 454, FieldExpression.witnessRow 455, FieldExpression.witnessRow 456, FieldExpression.witnessRow 457, FieldExpression.witnessRow 458, FieldExpression.witnessRow 459, FieldExpression.witnessRow 460, FieldExpression.witnessRow 461, FieldExpression.witnessRow 462, FieldExpression.witnessRow 463, FieldExpression.witnessRow 464, FieldExpression.witnessRow 465, FieldExpression.witnessRow 466, FieldExpression.witnessRow 467, FieldExpression.witnessRow 468, FieldExpression.witnessRow 469, FieldExpression.witnessRow 470, FieldExpression.witnessRow 471, FieldExpression.witnessRow 472, FieldExpression.witnessRow 473, FieldExpression.witnessRow 474, FieldExpression.witnessRow 475, FieldExpression.witnessRow 476, FieldExpression.witnessRow 477, FieldExpression.witnessRow 478, FieldExpression.witnessRow 479, FieldExpression.witnessRow 480, FieldExpression.witnessRow 481, FieldExpression.witnessRow 482, FieldExpression.witnessRow 483] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_019 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 608
      ([FieldExpression.witnessRow 484, FieldExpression.witnessRow 485, FieldExpression.witnessRow 486, FieldExpression.witnessRow 487, FieldExpression.witnessRow 488, FieldExpression.witnessRow 489, FieldExpression.witnessRow 490, FieldExpression.witnessRow 491, FieldExpression.witnessRow 492, FieldExpression.witnessRow 493, FieldExpression.witnessRow 494, FieldExpression.witnessRow 495, FieldExpression.witnessRow 496, FieldExpression.witnessRow 497, FieldExpression.witnessRow 498, FieldExpression.witnessRow 499, FieldExpression.witnessRow 500, FieldExpression.witnessRow 501, FieldExpression.witnessRow 502, FieldExpression.witnessRow 503, FieldExpression.witnessRow 504, FieldExpression.witnessRow 505, FieldExpression.witnessRow 506, FieldExpression.witnessRow 507, FieldExpression.witnessRow 508, FieldExpression.witnessRow 509, FieldExpression.witnessRow 510, FieldExpression.witnessRow 511, FieldExpression.witnessRow 512, FieldExpression.witnessRow 513, FieldExpression.witnessRow 514, FieldExpression.witnessRow 515] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_020 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 640
      ([FieldExpression.witnessRow 516, FieldExpression.witnessRow 517, FieldExpression.witnessRow 518, FieldExpression.witnessRow 519, FieldExpression.witnessRow 520, FieldExpression.witnessRow 521, FieldExpression.witnessRow 522, FieldExpression.witnessRow 523, FieldExpression.witnessRow 524, FieldExpression.witnessRow 525, FieldExpression.witnessRow 526, FieldExpression.witnessRow 527, FieldExpression.witnessRow 528, FieldExpression.witnessRow 529, FieldExpression.witnessRow 530, FieldExpression.witnessRow 531, FieldExpression.witnessRow 532, FieldExpression.witnessRow 533, FieldExpression.witnessRow 534, FieldExpression.witnessRow 535, FieldExpression.witnessRow 536, FieldExpression.witnessRow 537, FieldExpression.witnessRow 538, FieldExpression.witnessRow 539, FieldExpression.witnessRow 540, FieldExpression.witnessRow 541, FieldExpression.witnessRow 542, FieldExpression.witnessRow 543, FieldExpression.witnessRow 544, FieldExpression.witnessRow 545, FieldExpression.witnessRow 546, FieldExpression.witnessRow 547] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_021 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 672
      ([FieldExpression.witnessRow 548, FieldExpression.witnessRow 549, FieldExpression.witnessRow 550, FieldExpression.witnessRow 551, FieldExpression.witnessRow 552, FieldExpression.witnessRow 553, FieldExpression.witnessRow 554, FieldExpression.witnessRow 555, FieldExpression.witnessRow 556, FieldExpression.witnessRow 557, FieldExpression.witnessRow 558, FieldExpression.witnessRow 559, FieldExpression.witnessRow 560, FieldExpression.witnessRow 561, FieldExpression.witnessRow 562, FieldExpression.witnessRow 563, FieldExpression.witnessRow 564, FieldExpression.witnessRow 565, FieldExpression.witnessRow 566, FieldExpression.witnessRow 567, FieldExpression.witnessRow 568, FieldExpression.witnessRow 569, FieldExpression.witnessRow 570, FieldExpression.witnessRow 571, FieldExpression.witnessRow 572, FieldExpression.witnessRow 573, FieldExpression.witnessRow 574, FieldExpression.witnessRow 575, FieldExpression.witnessRow 576, FieldExpression.witnessRow 577, FieldExpression.witnessRow 578, FieldExpression.witnessRow 579] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_022 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 704
      ([FieldExpression.witnessRow 580, FieldExpression.witnessRow 581, FieldExpression.witnessRow 582, FieldExpression.witnessRow 583, FieldExpression.witnessRow 584, FieldExpression.witnessRow 585, FieldExpression.witnessRow 586, FieldExpression.witnessRow 587, FieldExpression.witnessRow 588, FieldExpression.witnessRow 589, FieldExpression.witnessRow 590, FieldExpression.witnessRow 591, FieldExpression.witnessRow 592, FieldExpression.witnessRow 593, FieldExpression.witnessRow 594, FieldExpression.witnessRow 595, FieldExpression.witnessRow 596, FieldExpression.witnessRow 597, FieldExpression.witnessRow 598, FieldExpression.witnessRow 599, FieldExpression.witnessRow 600, FieldExpression.witnessRow 601, FieldExpression.witnessRow 602, FieldExpression.witnessRow 603, FieldExpression.witnessRow 604, FieldExpression.witnessRow 605, FieldExpression.witnessRow 606, FieldExpression.witnessRow 607, FieldExpression.witnessRow 608, FieldExpression.witnessRow 609, FieldExpression.witnessRow 610, FieldExpression.witnessRow 611] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_023 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 736
      ([FieldExpression.witnessRow 612, FieldExpression.witnessRow 613, FieldExpression.witnessRow 614, FieldExpression.witnessRow 615, FieldExpression.witnessRow 616, FieldExpression.witnessRow 617, FieldExpression.witnessRow 618, FieldExpression.witnessRow 619, FieldExpression.witnessRow 620, FieldExpression.witnessRow 621, FieldExpression.witnessRow 622, FieldExpression.witnessRow 623, FieldExpression.witnessRow 624, FieldExpression.witnessRow 625, FieldExpression.witnessRow 626, FieldExpression.witnessRow 627, FieldExpression.witnessRow 628, FieldExpression.witnessRow 629, FieldExpression.witnessRow 630, FieldExpression.witnessRow 631, FieldExpression.witnessRow 632, FieldExpression.witnessRow 633, FieldExpression.witnessRow 634, FieldExpression.witnessRow 635, FieldExpression.witnessRow 636, FieldExpression.witnessRow 637, FieldExpression.witnessRow 638, FieldExpression.witnessRow 639, FieldExpression.witnessRow 640, FieldExpression.witnessRow 641, FieldExpression.witnessRow 642, FieldExpression.witnessRow 643] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_024 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 768
      ([FieldExpression.witnessRow 644, FieldExpression.witnessRow 645, FieldExpression.witnessRow 646, FieldExpression.witnessRow 647, FieldExpression.witnessRow 648, FieldExpression.witnessRow 649, FieldExpression.witnessRow 650, FieldExpression.witnessRow 651, FieldExpression.witnessRow 652, FieldExpression.witnessRow 653, FieldExpression.witnessRow 654, FieldExpression.witnessRow 655, FieldExpression.witnessRow 656, FieldExpression.witnessRow 657, FieldExpression.witnessRow 658, FieldExpression.witnessRow 659, FieldExpression.witnessRow 660, FieldExpression.witnessRow 661, FieldExpression.witnessRow 662, FieldExpression.witnessRow 663, FieldExpression.witnessRow 664, FieldExpression.witnessRow 665, FieldExpression.witnessRow 666, FieldExpression.witnessRow 667, FieldExpression.witnessRow 668, FieldExpression.witnessRow 669, FieldExpression.witnessRow 670, FieldExpression.witnessRow 671, FieldExpression.witnessRow 672, FieldExpression.witnessRow 673, FieldExpression.witnessRow 674, FieldExpression.witnessRow 675] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_025 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 800
      ([FieldExpression.witnessRow 676, FieldExpression.witnessRow 677, FieldExpression.witnessRow 678, FieldExpression.witnessRow 679, FieldExpression.witnessRow 680, FieldExpression.witnessRow 681, FieldExpression.witnessRow 682, FieldExpression.witnessRow 683, FieldExpression.witnessRow 684, FieldExpression.witnessRow 685, FieldExpression.sub 4 1, FieldExpression.mul 4 810, FieldExpression.sub 5 1, FieldExpression.mul 5 812, FieldExpression.sub 6 1, FieldExpression.mul 6 814, FieldExpression.sub 7 1, FieldExpression.mul 7 816, FieldExpression.sub 49 1, FieldExpression.mul 49 818, FieldExpression.sub 62 1, FieldExpression.mul 62 820, FieldExpression.sub 65 1, FieldExpression.mul 65 822, FieldExpression.sub 87 1, FieldExpression.sub 87 2, FieldExpression.mul 87 824, FieldExpression.mul 825 826, FieldExpression.inverse 2, FieldExpression.constant 3, FieldExpression.sub 829 87, FieldExpression.mul 87 830] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_026 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 832
      ([FieldExpression.mul 828 831, FieldExpression.sub 2 87, FieldExpression.mul 87 833, FieldExpression.sub 62 832, FieldExpression.sub 65 834, FieldExpression.sub 63 88, FieldExpression.sub 64 89, FieldExpression.sub 66 90, FieldExpression.sub 126 1, FieldExpression.mul 126 840, FieldExpression.sub 127 1, FieldExpression.mul 127 842, FieldExpression.sub 128 1, FieldExpression.mul 128 844, FieldExpression.sub 129 1, FieldExpression.mul 129 846, FieldExpression.sub 130 1, FieldExpression.mul 130 848, FieldExpression.sub 131 1, FieldExpression.mul 131 850, FieldExpression.sub 132 1, FieldExpression.mul 132 852, FieldExpression.sub 133 1, FieldExpression.mul 133 854, FieldExpression.sub 134 1, FieldExpression.mul 134 856, FieldExpression.sub 135 1, FieldExpression.mul 135 858, FieldExpression.sub 136 1, FieldExpression.mul 136 860, FieldExpression.sub 137 1, FieldExpression.mul 137 862] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_027 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 864
      ([FieldExpression.sub 138 1, FieldExpression.mul 138 864, FieldExpression.sub 139 1, FieldExpression.mul 139 866, FieldExpression.sub 140 1, FieldExpression.mul 140 868, FieldExpression.sub 141 1, FieldExpression.mul 141 870, FieldExpression.sub 142 1, FieldExpression.mul 142 872, FieldExpression.sub 143 1, FieldExpression.mul 143 874, FieldExpression.sub 144 1, FieldExpression.mul 144 876, FieldExpression.sub 145 1, FieldExpression.mul 145 878, FieldExpression.sub 146 1, FieldExpression.mul 146 880, FieldExpression.sub 147 1, FieldExpression.mul 147 882, FieldExpression.sub 148 1, FieldExpression.mul 148 884, FieldExpression.sub 149 1, FieldExpression.mul 149 886, FieldExpression.sub 150 1, FieldExpression.mul 150 888, FieldExpression.sub 151 1, FieldExpression.mul 151 890, FieldExpression.sub 152 1, FieldExpression.mul 152 892, FieldExpression.sub 153 1, FieldExpression.mul 153 894] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_028 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 896
      ([FieldExpression.sub 154 1, FieldExpression.mul 154 896, FieldExpression.sub 155 1, FieldExpression.mul 155 898, FieldExpression.sub 156 1, FieldExpression.mul 156 900, FieldExpression.sub 157 1, FieldExpression.mul 157 902, FieldExpression.sub 125 58, FieldExpression.constant 4294967294, FieldExpression.selectEqual 58 905 1 904, FieldExpression.sub 125 59, FieldExpression.selectEqual 59 905 1 907, FieldExpression.mul 906 908, FieldExpression.sub 125 60, FieldExpression.selectEqual 60 905 1 910, FieldExpression.mul 909 911, FieldExpression.sub 125 61, FieldExpression.selectEqual 61 905 1 913, FieldExpression.mul 912 914, FieldExpression.mul 4 915, FieldExpression.sub 160 1, FieldExpression.mul 160 917, FieldExpression.sub 161 1, FieldExpression.mul 161 919, FieldExpression.sub 162 1, FieldExpression.mul 162 921, FieldExpression.sub 163 1, FieldExpression.mul 163 923, FieldExpression.sub 164 1, FieldExpression.mul 164 925, FieldExpression.sub 165 1] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_029 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 928
      ([FieldExpression.mul 165 927, FieldExpression.sub 166 1, FieldExpression.mul 166 929, FieldExpression.sub 167 1, FieldExpression.mul 167 931, FieldExpression.sub 168 1, FieldExpression.mul 168 933, FieldExpression.sub 169 1, FieldExpression.mul 169 935, FieldExpression.sub 170 1, FieldExpression.mul 170 937, FieldExpression.sub 171 1, FieldExpression.mul 171 939, FieldExpression.sub 172 1, FieldExpression.mul 172 941, FieldExpression.sub 173 1, FieldExpression.mul 173 943, FieldExpression.sub 174 1, FieldExpression.mul 174 945, FieldExpression.sub 175 1, FieldExpression.mul 175 947, FieldExpression.sub 176 1, FieldExpression.mul 176 949, FieldExpression.sub 177 1, FieldExpression.mul 177 951, FieldExpression.sub 178 1, FieldExpression.mul 178 953, FieldExpression.sub 179 1, FieldExpression.mul 179 955, FieldExpression.sub 180 1, FieldExpression.mul 180 957, FieldExpression.sub 181 1] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_030 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 960
      ([FieldExpression.mul 181 959, FieldExpression.sub 182 1, FieldExpression.mul 182 961, FieldExpression.sub 183 1, FieldExpression.mul 183 963, FieldExpression.sub 184 1, FieldExpression.mul 184 965, FieldExpression.sub 185 1, FieldExpression.mul 185 967, FieldExpression.sub 186 1, FieldExpression.mul 186 969, FieldExpression.sub 187 1, FieldExpression.mul 187 971, FieldExpression.sub 188 1, FieldExpression.mul 188 973, FieldExpression.sub 189 1, FieldExpression.mul 189 975, FieldExpression.sub 190 1, FieldExpression.mul 190 977, FieldExpression.sub 191 1, FieldExpression.mul 191 979, FieldExpression.sub 159 58, FieldExpression.selectEqual 58 905 1 981, FieldExpression.sub 159 59, FieldExpression.selectEqual 59 905 1 983, FieldExpression.mul 982 984, FieldExpression.sub 159 60, FieldExpression.selectEqual 60 905 1 986, FieldExpression.mul 985 987, FieldExpression.sub 159 61, FieldExpression.selectEqual 61 905 1 989, FieldExpression.mul 988 990] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_031 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 992
      ([FieldExpression.mul 5 991, FieldExpression.sub 193 58, FieldExpression.selectEqual 58 905 1 993, FieldExpression.sub 193 59, FieldExpression.selectEqual 59 905 1 995, FieldExpression.mul 994 996, FieldExpression.sub 193 60, FieldExpression.selectEqual 60 905 1 998, FieldExpression.mul 997 999, FieldExpression.sub 193 61, FieldExpression.selectEqual 61 905 1 1001, FieldExpression.mul 1000 1002, FieldExpression.mul 6 1003, FieldExpression.sub 1 6, FieldExpression.mul 194 1005, FieldExpression.mul 195 1005, FieldExpression.mul 196 1005, FieldExpression.mul 197 1005, FieldExpression.mul 198 1005, FieldExpression.mul 199 1005, FieldExpression.sub 205 58, FieldExpression.selectEqual 58 905 1 1012, FieldExpression.sub 205 59, FieldExpression.selectEqual 59 905 1 1014, FieldExpression.mul 1013 1015, FieldExpression.sub 205 60, FieldExpression.selectEqual 60 905 1 1017, FieldExpression.mul 1016 1018, FieldExpression.sub 205 61, FieldExpression.selectEqual 61 905 1 1020, FieldExpression.mul 1019 1021, FieldExpression.mul 7 1022] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_032 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1024
      ([FieldExpression.sub 1 7, FieldExpression.mul 206 1024, FieldExpression.mul 207 1024, FieldExpression.mul 208 1024, FieldExpression.mul 209 1024, FieldExpression.mul 210 1024, FieldExpression.mul 211 1024, FieldExpression.sub 63 58, FieldExpression.selectEqual 58 905 1 1031, FieldExpression.sub 63 59, FieldExpression.selectEqual 59 905 1 1033, FieldExpression.mul 1032 1034, FieldExpression.sub 63 60, FieldExpression.selectEqual 60 905 1 1036, FieldExpression.mul 1035 1037, FieldExpression.sub 63 61, FieldExpression.selectEqual 61 905 1 1039, FieldExpression.mul 1038 1040, FieldExpression.mul 832 1041, FieldExpression.add 49 49, FieldExpression.mul 50 1043, FieldExpression.sub 50 1044, FieldExpression.add 65 65, FieldExpression.mul 66 1046, FieldExpression.sub 66 1047, FieldExpression.sub 48 1045, FieldExpression.sub 58 59, FieldExpression.selectEqual 59 905 1 1050, FieldExpression.sub 58 60, FieldExpression.selectEqual 60 905 1 1052, FieldExpression.mul 1051 1053, FieldExpression.sub 58 61] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_033 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1056
      ([FieldExpression.selectEqual 61 905 1 1055, FieldExpression.mul 1054 1056, FieldExpression.mul 908 911, FieldExpression.mul 914 1058, FieldExpression.inverse 1057, FieldExpression.mul 1059 1060, FieldExpression.selectEqual 58 905 0 1061, FieldExpression.sub 59 58, FieldExpression.selectEqual 58 905 1 1063, FieldExpression.sub 59 60, FieldExpression.selectEqual 60 905 1 1065, FieldExpression.mul 1064 1066, FieldExpression.sub 59 61, FieldExpression.selectEqual 61 905 1 1068, FieldExpression.mul 1067 1069, FieldExpression.mul 906 911, FieldExpression.mul 914 1071, FieldExpression.inverse 1070, FieldExpression.mul 1072 1073, FieldExpression.selectEqual 59 905 0 1074, FieldExpression.sub 60 58, FieldExpression.selectEqual 58 905 1 1076, FieldExpression.sub 60 59, FieldExpression.selectEqual 59 905 1 1078, FieldExpression.mul 1077 1079, FieldExpression.sub 60 61, FieldExpression.selectEqual 61 905 1 1081, FieldExpression.mul 1080 1082, FieldExpression.mul 909 914, FieldExpression.inverse 1083, FieldExpression.mul 1084 1085, FieldExpression.selectEqual 60 905 0 1086] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_034 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1088
      ([FieldExpression.sub 61 58, FieldExpression.selectEqual 58 905 1 1088, FieldExpression.sub 61 59, FieldExpression.selectEqual 59 905 1 1090, FieldExpression.mul 1089 1091, FieldExpression.sub 61 60, FieldExpression.selectEqual 60 905 1 1093, FieldExpression.mul 1092 1094, FieldExpression.inverse 1095, FieldExpression.mul 912 1096, FieldExpression.selectEqual 61 905 0 1097, FieldExpression.mul 4 124, FieldExpression.mul 1062 1099, FieldExpression.mul 984 987, FieldExpression.mul 990 1101, FieldExpression.mul 1060 1102, FieldExpression.selectEqual 58 905 0 1103, FieldExpression.mul 982 987, FieldExpression.mul 990 1105, FieldExpression.mul 1073 1106, FieldExpression.selectEqual 59 905 0 1107, FieldExpression.mul 985 990, FieldExpression.mul 1085 1109, FieldExpression.selectEqual 60 905 0 1110, FieldExpression.mul 988 1096, FieldExpression.selectEqual 61 905 0 1112, FieldExpression.mul 5 158, FieldExpression.mul 1104 1114, FieldExpression.add 1100 1115, FieldExpression.mul 996 999, FieldExpression.mul 1002 1117, FieldExpression.mul 1060 1118] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_035 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1120
      ([FieldExpression.selectEqual 58 905 0 1119, FieldExpression.mul 994 999, FieldExpression.mul 1002 1121, FieldExpression.mul 1073 1122, FieldExpression.selectEqual 59 905 0 1123, FieldExpression.mul 997 1002, FieldExpression.mul 1085 1125, FieldExpression.selectEqual 60 905 0 1126, FieldExpression.mul 1000 1096, FieldExpression.selectEqual 61 905 0 1128, FieldExpression.mul 6 192, FieldExpression.mul 1120 1130, FieldExpression.sub 1116 1131, FieldExpression.mul 1015 1018, FieldExpression.mul 1021 1133, FieldExpression.mul 1060 1134, FieldExpression.selectEqual 58 905 0 1135, FieldExpression.mul 1013 1018, FieldExpression.mul 1021 1137, FieldExpression.mul 1073 1138, FieldExpression.selectEqual 59 905 0 1139, FieldExpression.mul 1016 1021, FieldExpression.mul 1085 1141, FieldExpression.selectEqual 60 905 0 1142, FieldExpression.mul 1019 1096, FieldExpression.selectEqual 61 905 0 1144, FieldExpression.mul 7 204, FieldExpression.mul 1136 1146, FieldExpression.sub 1132 1147, FieldExpression.sub 1148 1049, FieldExpression.mul 1075 1099, FieldExpression.mul 1108 1114] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_036 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1152
      ([FieldExpression.add 1150 1151, FieldExpression.mul 1124 1130, FieldExpression.sub 1152 1153, FieldExpression.mul 1140 1146, FieldExpression.sub 1154 1155, FieldExpression.mul 832 1048, FieldExpression.selectEqual 59 63 1157 0, FieldExpression.sub 1156 1158, FieldExpression.mul 1087 1099, FieldExpression.mul 1111 1114, FieldExpression.add 1160 1161, FieldExpression.mul 1127 1130, FieldExpression.sub 1162 1163, FieldExpression.mul 1143 1146, FieldExpression.sub 1164 1165, FieldExpression.selectEqual 60 63 1157 0, FieldExpression.sub 1166 1167, FieldExpression.mul 1098 1099, FieldExpression.mul 1113 1114, FieldExpression.add 1169 1170, FieldExpression.mul 1129 1130, FieldExpression.sub 1171 1172, FieldExpression.mul 1145 1146, FieldExpression.sub 1173 1174, FieldExpression.selectEqual 61 63 1157 0, FieldExpression.sub 1175 1176, FieldExpression.sub 371 1, FieldExpression.sub 371 2, FieldExpression.sub 371 829, FieldExpression.mul 371 1178, FieldExpression.mul 1179 1181, FieldExpression.mul 1180 1182] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_037 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1184
      ([FieldExpression.sub 372 1, FieldExpression.sub 372 2, FieldExpression.sub 372 829, FieldExpression.mul 372 1184, FieldExpression.mul 1185 1187, FieldExpression.mul 1186 1188, FieldExpression.sub 373 1, FieldExpression.sub 373 2, FieldExpression.sub 373 829, FieldExpression.mul 373 1190, FieldExpression.mul 1191 1193, FieldExpression.mul 1192 1194, FieldExpression.sub 374 1, FieldExpression.sub 374 2, FieldExpression.sub 374 829, FieldExpression.mul 374 1196, FieldExpression.mul 1197 1199, FieldExpression.mul 1198 1200, FieldExpression.sub 375 1, FieldExpression.mul 375 1202, FieldExpression.sub 378 377, FieldExpression.mul 379 1204, FieldExpression.add 377 1205, FieldExpression.sub 376 1206, FieldExpression.sub 382 381, FieldExpression.mul 383 1208, FieldExpression.add 381 1209, FieldExpression.sub 380 1210, FieldExpression.sub 386 385, FieldExpression.mul 387 1212, FieldExpression.add 385 1213, FieldExpression.sub 384 1214] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_038 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1216
      ([FieldExpression.sub 390 389, FieldExpression.mul 391 1216, FieldExpression.add 389 1217, FieldExpression.sub 388 1218, FieldExpression.sub 394 393, FieldExpression.mul 395 1220, FieldExpression.add 393 1221, FieldExpression.sub 392 1222, FieldExpression.sub 398 397, FieldExpression.mul 399 1224, FieldExpression.add 397 1225, FieldExpression.sub 396 1226, FieldExpression.sub 402 401, FieldExpression.mul 403 1228, FieldExpression.add 401 1229, FieldExpression.sub 400 1230, FieldExpression.sub 404 405, FieldExpression.mul 406 1232, FieldExpression.add 217 218, FieldExpression.sub 216 1, FieldExpression.mul 216 1235, FieldExpression.sub 217 1, FieldExpression.mul 217 1237, FieldExpression.sub 218 1, FieldExpression.mul 218 1239, FieldExpression.add 216 217, FieldExpression.add 218 1241, FieldExpression.sub 1242 1, FieldExpression.mul 216 262, FieldExpression.mul 216 269, FieldExpression.mul 216 263, FieldExpression.mul 216 270] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_039 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1248
      ([FieldExpression.mul 216 264, FieldExpression.mul 216 271, FieldExpression.mul 216 265, FieldExpression.mul 216 272, FieldExpression.mul 216 266, FieldExpression.mul 216 273, FieldExpression.mul 216 267, FieldExpression.mul 216 274, FieldExpression.mul 216 268, FieldExpression.mul 216 275, FieldExpression.mul 216 276, FieldExpression.mul 216 277, FieldExpression.mul 216 278, FieldExpression.mul 216 285, FieldExpression.mul 216 292, FieldExpression.mul 216 293, FieldExpression.mul 216 279, FieldExpression.mul 216 280, FieldExpression.mul 216 281, FieldExpression.mul 216 282, FieldExpression.mul 216 283, FieldExpression.mul 216 284, FieldExpression.mul 216 286, FieldExpression.mul 216 287, FieldExpression.mul 216 288, FieldExpression.mul 216 289, FieldExpression.mul 216 290, FieldExpression.mul 216 291, FieldExpression.mul 216 294, FieldExpression.mul 216 295, FieldExpression.mul 216 296, FieldExpression.mul 216 297] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_040 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1280
      ([FieldExpression.mul 216 298, FieldExpression.mul 216 299, FieldExpression.mul 216 300, FieldExpression.mul 216 301, FieldExpression.mul 216 302, FieldExpression.mul 216 303, FieldExpression.mul 216 304, FieldExpression.mul 216 305, FieldExpression.mul 216 306, FieldExpression.mul 216 307, FieldExpression.mul 216 308, FieldExpression.mul 216 309, FieldExpression.mul 216 310, FieldExpression.mul 216 311, FieldExpression.mul 216 312, FieldExpression.mul 216 313, FieldExpression.mul 216 314, FieldExpression.mul 216 315, FieldExpression.mul 216 316, FieldExpression.mul 216 317, FieldExpression.mul 216 318, FieldExpression.mul 216 319, FieldExpression.mul 216 350, FieldExpression.mul 216 351, FieldExpression.mul 216 352, FieldExpression.mul 216 353, FieldExpression.mul 216 354, FieldExpression.mul 216 355, FieldExpression.mul 216 320, FieldExpression.mul 216 321, FieldExpression.mul 216 322, FieldExpression.mul 216 323] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_041 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1312
      ([FieldExpression.mul 216 324, FieldExpression.mul 216 325, FieldExpression.mul 216 326, FieldExpression.mul 216 327, FieldExpression.mul 216 328, FieldExpression.mul 216 329, FieldExpression.mul 216 330, FieldExpression.mul 216 331, FieldExpression.mul 216 332, FieldExpression.mul 216 333, FieldExpression.mul 216 334, FieldExpression.mul 216 335, FieldExpression.mul 216 336, FieldExpression.mul 216 337, FieldExpression.mul 216 338, FieldExpression.mul 216 339, FieldExpression.mul 216 340, FieldExpression.mul 216 341, FieldExpression.mul 216 342, FieldExpression.mul 216 343, FieldExpression.mul 216 344, FieldExpression.mul 216 345, FieldExpression.mul 216 346, FieldExpression.mul 216 347, FieldExpression.mul 216 348, FieldExpression.mul 216 349, FieldExpression.mul 216 356, FieldExpression.mul 216 357, FieldExpression.mul 216 358, FieldExpression.mul 216 359, FieldExpression.mul 216 360, FieldExpression.mul 216 361] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_042 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1344
      ([FieldExpression.mul 216 362, FieldExpression.mul 216 363, FieldExpression.mul 216 364, FieldExpression.mul 216 365, FieldExpression.mul 216 366, FieldExpression.mul 216 367, FieldExpression.mul 216 368, FieldExpression.mul 216 369, FieldExpression.mul 216 370, FieldExpression.mul 216 229, FieldExpression.mul 217 238, FieldExpression.mul 218 252, FieldExpression.add 1354 1355, FieldExpression.add 1353 1356, FieldExpression.mul 4 1357, FieldExpression.sub 219 1358, FieldExpression.mul 216 230, FieldExpression.mul 217 234, FieldExpression.mul 218 248, FieldExpression.add 1361 1362, FieldExpression.add 1360 1363, FieldExpression.mul 4 1364, FieldExpression.sub 221 1365, FieldExpression.mul 216 231, FieldExpression.mul 217 235, FieldExpression.mul 218 249, FieldExpression.add 1368 1369, FieldExpression.add 1367 1370, FieldExpression.mul 4 1371, FieldExpression.sub 222 1372, FieldExpression.mul 216 232, FieldExpression.mul 217 236] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_043 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1376
      ([FieldExpression.mul 218 250, FieldExpression.add 1375 1376, FieldExpression.add 1374 1377, FieldExpression.mul 4 1378, FieldExpression.sub 223 1379, FieldExpression.mul 216 233, FieldExpression.mul 217 237, FieldExpression.mul 218 251, FieldExpression.add 1382 1383, FieldExpression.add 1381 1384, FieldExpression.mul 4 1385, FieldExpression.sub 224 1386, FieldExpression.mul 217 229, FieldExpression.mul 218 238, FieldExpression.add 1388 1389, FieldExpression.add 1353 1390, FieldExpression.mul 5 1391, FieldExpression.sub 220 1392, FieldExpression.mul 217 230, FieldExpression.mul 218 234, FieldExpression.add 1394 1395, FieldExpression.add 1360 1396, FieldExpression.mul 5 1397, FieldExpression.sub 225 1398, FieldExpression.mul 217 231, FieldExpression.mul 218 235, FieldExpression.add 1400 1401, FieldExpression.add 1367 1402, FieldExpression.mul 5 1403, FieldExpression.sub 226 1404, FieldExpression.mul 217 232, FieldExpression.mul 218 236] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_044 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1408
      ([FieldExpression.add 1406 1407, FieldExpression.add 1374 1408, FieldExpression.mul 5 1409, FieldExpression.sub 227 1410, FieldExpression.mul 217 233, FieldExpression.mul 218 237, FieldExpression.add 1412 1413, FieldExpression.add 1381 1414, FieldExpression.mul 5 1415, FieldExpression.sub 228 1416, FieldExpression.mul 217 810, FieldExpression.mul 217 812, FieldExpression.mul 217 814, FieldExpression.mul 218 810, FieldExpression.mul 218 812, FieldExpression.sub 200 241, FieldExpression.mul 217 1423, FieldExpression.sub 201 242, FieldExpression.mul 217 1425, FieldExpression.sub 202 243, FieldExpression.mul 217 1427, FieldExpression.sub 203 244, FieldExpression.mul 217 1429, FieldExpression.sub 294 1, FieldExpression.mul 294 1431, FieldExpression.mul 1234 1432, FieldExpression.sub 295 1, FieldExpression.mul 295 1434, FieldExpression.mul 1234 1435, FieldExpression.sub 296 1, FieldExpression.mul 296 1437, FieldExpression.mul 1234 1438] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_045 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1440
      ([FieldExpression.sub 297 1, FieldExpression.mul 297 1440, FieldExpression.mul 1234 1441, FieldExpression.sub 298 1, FieldExpression.mul 298 1443, FieldExpression.mul 1234 1444, FieldExpression.sub 299 1, FieldExpression.mul 299 1446, FieldExpression.mul 1234 1447, FieldExpression.add 294 295, FieldExpression.add 296 1449, FieldExpression.add 297 1450, FieldExpression.add 298 1451, FieldExpression.add 299 1452, FieldExpression.sub 1453 1, FieldExpression.mul 1234 1454, FieldExpression.mul 2 295, FieldExpression.add 294 1456, FieldExpression.mul 296 829, FieldExpression.add 1457 1458, FieldExpression.constant 4, FieldExpression.mul 297 1460, FieldExpression.add 1459 1461, FieldExpression.constant 5, FieldExpression.mul 298 1463, FieldExpression.add 1462 1464, FieldExpression.constant 6, FieldExpression.mul 299 1466, FieldExpression.add 1465 1467, FieldExpression.sub 276 1468, FieldExpression.mul 1234 1469, FieldExpression.sub 300 1] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_046 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1472
      ([FieldExpression.mul 300 1471, FieldExpression.mul 1234 1472, FieldExpression.sub 301 1, FieldExpression.mul 301 1474, FieldExpression.mul 1234 1475, FieldExpression.sub 302 1, FieldExpression.mul 302 1477, FieldExpression.mul 1234 1478, FieldExpression.sub 303 1, FieldExpression.mul 303 1480, FieldExpression.mul 1234 1481, FieldExpression.sub 304 1, FieldExpression.mul 304 1483, FieldExpression.mul 1234 1484, FieldExpression.sub 305 1, FieldExpression.mul 305 1486, FieldExpression.mul 1234 1487, FieldExpression.add 300 301, FieldExpression.add 302 1489, FieldExpression.add 303 1490, FieldExpression.add 304 1491, FieldExpression.add 305 1492, FieldExpression.sub 1493 1, FieldExpression.mul 1234 1494, FieldExpression.mul 2 301, FieldExpression.add 300 1496, FieldExpression.mul 302 829, FieldExpression.add 1497 1498, FieldExpression.mul 303 1460, FieldExpression.add 1499 1500, FieldExpression.mul 304 1463, FieldExpression.add 1501 1502] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_047 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1504
      ([FieldExpression.mul 305 1466, FieldExpression.add 1503 1504, FieldExpression.sub 277 1505, FieldExpression.mul 1234 1506, FieldExpression.mul 295 300, FieldExpression.mul 296 1489, FieldExpression.add 1508 1509, FieldExpression.mul 297 1490, FieldExpression.add 1510 1511, FieldExpression.mul 298 1491, FieldExpression.add 1512 1513, FieldExpression.mul 299 1492, FieldExpression.add 1514 1515, FieldExpression.mul 1234 1516, FieldExpression.sub 306 1, FieldExpression.mul 306 1518, FieldExpression.mul 1234 1519, FieldExpression.sub 307 1, FieldExpression.mul 307 1521, FieldExpression.mul 1234 1522, FieldExpression.sub 308 1, FieldExpression.mul 308 1524, FieldExpression.mul 1234 1525, FieldExpression.sub 309 1, FieldExpression.mul 309 1527, FieldExpression.mul 1234 1528, FieldExpression.sub 310 1, FieldExpression.mul 310 1530, FieldExpression.mul 1234 1531, FieldExpression.sub 311 1, FieldExpression.mul 311 1533, FieldExpression.mul 1234 1534] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_048 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1536
      ([FieldExpression.sub 312 1, FieldExpression.mul 312 1536, FieldExpression.mul 1234 1537, FieldExpression.add 306 307, FieldExpression.add 308 1539, FieldExpression.add 309 1540, FieldExpression.add 310 1541, FieldExpression.add 311 1542, FieldExpression.add 312 1543, FieldExpression.sub 1544 1, FieldExpression.mul 1234 1545, FieldExpression.mul 2 308, FieldExpression.add 307 1547, FieldExpression.mul 309 829, FieldExpression.add 1548 1549, FieldExpression.mul 310 1460, FieldExpression.add 1550 1551, FieldExpression.mul 311 1463, FieldExpression.add 1552 1553, FieldExpression.mul 312 1466, FieldExpression.add 1554 1555, FieldExpression.sub 278 1556, FieldExpression.mul 1234 1557, FieldExpression.sub 313 1, FieldExpression.mul 313 1559, FieldExpression.mul 217 1560, FieldExpression.sub 314 1, FieldExpression.mul 314 1562, FieldExpression.mul 217 1563, FieldExpression.sub 315 1, FieldExpression.mul 315 1565, FieldExpression.mul 217 1566] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_049 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1568
      ([FieldExpression.sub 316 1, FieldExpression.mul 316 1568, FieldExpression.mul 217 1569, FieldExpression.sub 317 1, FieldExpression.mul 317 1571, FieldExpression.mul 217 1572, FieldExpression.sub 318 1, FieldExpression.mul 318 1574, FieldExpression.mul 217 1575, FieldExpression.sub 319 1, FieldExpression.mul 319 1577, FieldExpression.mul 217 1578, FieldExpression.add 313 314, FieldExpression.add 315 1580, FieldExpression.add 316 1581, FieldExpression.add 317 1582, FieldExpression.add 318 1583, FieldExpression.add 319 1584, FieldExpression.sub 1585 1, FieldExpression.mul 217 1586, FieldExpression.mul 2 315, FieldExpression.add 314 1588, FieldExpression.mul 316 829, FieldExpression.add 1589 1590, FieldExpression.mul 317 1460, FieldExpression.add 1591 1592, FieldExpression.mul 318 1463, FieldExpression.add 1593 1594, FieldExpression.mul 319 1466, FieldExpression.add 1595 1596, FieldExpression.sub 285 1597, FieldExpression.mul 217 1598] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_050 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1600
      ([FieldExpression.sub 285 278, FieldExpression.sub 1600 1, FieldExpression.mul 217 1601, FieldExpression.mul 217 312, FieldExpression.sub 279 1, FieldExpression.mul 279 1604, FieldExpression.mul 1234 1605, FieldExpression.mul 279 1234, FieldExpression.sub 1 1493, FieldExpression.mul 1607 1608, FieldExpression.sub 280 1, FieldExpression.mul 280 1610, FieldExpression.mul 1234 1611, FieldExpression.mul 280 1234, FieldExpression.add 301 302, FieldExpression.add 303 1614, FieldExpression.add 304 1615, FieldExpression.add 305 1616, FieldExpression.sub 1 1617, FieldExpression.mul 1613 1618, FieldExpression.sub 281 1, FieldExpression.mul 281 1620, FieldExpression.mul 1234 1621, FieldExpression.mul 281 1234, FieldExpression.add 302 303, FieldExpression.add 304 1624, FieldExpression.add 305 1625, FieldExpression.sub 1 1626, FieldExpression.mul 1623 1627, FieldExpression.sub 282 1, FieldExpression.mul 282 1629, FieldExpression.mul 1234 1630] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_051 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1632
      ([FieldExpression.mul 282 1234, FieldExpression.add 303 304, FieldExpression.add 305 1633, FieldExpression.sub 1 1634, FieldExpression.mul 1632 1635, FieldExpression.sub 283 1, FieldExpression.mul 283 1637, FieldExpression.mul 1234 1638, FieldExpression.mul 283 1234, FieldExpression.add 304 305, FieldExpression.sub 1 1641, FieldExpression.mul 1640 1642, FieldExpression.sub 284 1, FieldExpression.mul 284 1644, FieldExpression.mul 1234 1645, FieldExpression.mul 284 1234, FieldExpression.sub 1 305, FieldExpression.mul 1647 1648, FieldExpression.add 279 280, FieldExpression.add 281 1650, FieldExpression.add 282 1651, FieldExpression.add 283 1652, FieldExpression.add 284 1653, FieldExpression.sub 278 1654, FieldExpression.mul 1234 1655, FieldExpression.sub 286 1, FieldExpression.mul 286 1657, FieldExpression.mul 217 1658, FieldExpression.mul 217 286, FieldExpression.mul 1608 1660, FieldExpression.sub 287 1, FieldExpression.mul 287 1662] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_052 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1664
      ([FieldExpression.mul 217 1663, FieldExpression.mul 217 287, FieldExpression.mul 1618 1665, FieldExpression.sub 288 1, FieldExpression.mul 288 1667, FieldExpression.mul 217 1668, FieldExpression.mul 217 288, FieldExpression.mul 1627 1670, FieldExpression.sub 289 1, FieldExpression.mul 289 1672, FieldExpression.mul 217 1673, FieldExpression.mul 217 289, FieldExpression.mul 1635 1675, FieldExpression.sub 290 1, FieldExpression.mul 290 1677, FieldExpression.mul 217 1678, FieldExpression.mul 217 290, FieldExpression.mul 1642 1680, FieldExpression.sub 291 1, FieldExpression.mul 291 1682, FieldExpression.mul 217 1683, FieldExpression.mul 217 291, FieldExpression.mul 1648 1685, FieldExpression.add 286 287, FieldExpression.add 288 1687, FieldExpression.add 289 1688, FieldExpression.add 290 1689, FieldExpression.add 291 1690, FieldExpression.sub 285 1691, FieldExpression.mul 217 1692, FieldExpression.mul 217 350, FieldExpression.mul 279 1694] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_053 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1696
      ([FieldExpression.sub 286 279, FieldExpression.sub 1696 350, FieldExpression.mul 217 1697, FieldExpression.mul 217 351, FieldExpression.mul 280 1699, FieldExpression.sub 287 280, FieldExpression.sub 1701 351, FieldExpression.mul 217 1702, FieldExpression.mul 217 352, FieldExpression.mul 281 1704, FieldExpression.sub 288 281, FieldExpression.sub 1706 352, FieldExpression.mul 217 1707, FieldExpression.mul 217 353, FieldExpression.mul 282 1709, FieldExpression.sub 289 282, FieldExpression.sub 1711 353, FieldExpression.mul 217 1712, FieldExpression.mul 217 354, FieldExpression.mul 283 1714, FieldExpression.sub 290 283, FieldExpression.sub 1716 354, FieldExpression.mul 217 1717, FieldExpression.mul 217 355, FieldExpression.mul 284 1719, FieldExpression.sub 291 284, FieldExpression.sub 1721 355, FieldExpression.mul 217 1722, FieldExpression.mul 217 292, FieldExpression.mul 217 293, FieldExpression.sub 350 1, FieldExpression.mul 350 1726] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_054 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1728
      ([FieldExpression.mul 217 1727, FieldExpression.sub 351 1, FieldExpression.mul 351 1729, FieldExpression.mul 217 1730, FieldExpression.sub 352 1, FieldExpression.mul 352 1732, FieldExpression.mul 217 1733, FieldExpression.sub 353 1, FieldExpression.mul 353 1735, FieldExpression.mul 217 1736, FieldExpression.sub 354 1, FieldExpression.mul 354 1738, FieldExpression.mul 217 1739, FieldExpression.sub 355 1, FieldExpression.mul 355 1741, FieldExpression.mul 217 1742, FieldExpression.add 350 351, FieldExpression.add 352 1744, FieldExpression.add 353 1745, FieldExpression.add 354 1746, FieldExpression.add 355 1747, FieldExpression.sub 1748 1, FieldExpression.mul 217 1749, FieldExpression.mul 1608 1694, FieldExpression.sub 229 320, FieldExpression.mul 1694 1752, FieldExpression.sub 230 321, FieldExpression.mul 1694 1754, FieldExpression.sub 231 322, FieldExpression.mul 1694 1756, FieldExpression.sub 232 323, FieldExpression.mul 1694 1758] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_055 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1760
      ([FieldExpression.sub 233 324, FieldExpression.mul 1694 1760, FieldExpression.mul 1618 1699, FieldExpression.sub 229 325, FieldExpression.mul 1699 1763, FieldExpression.sub 230 326, FieldExpression.mul 1699 1765, FieldExpression.sub 231 327, FieldExpression.mul 1699 1767, FieldExpression.sub 232 328, FieldExpression.mul 1699 1769, FieldExpression.sub 233 329, FieldExpression.mul 1699 1771, FieldExpression.mul 1627 1704, FieldExpression.sub 229 330, FieldExpression.mul 1704 1774, FieldExpression.sub 230 331, FieldExpression.mul 1704 1776, FieldExpression.sub 231 332, FieldExpression.mul 1704 1778, FieldExpression.sub 232 333, FieldExpression.mul 1704 1780, FieldExpression.sub 233 334, FieldExpression.mul 1704 1782, FieldExpression.mul 1635 1709, FieldExpression.sub 229 335, FieldExpression.mul 1709 1785, FieldExpression.sub 230 336, FieldExpression.mul 1709 1787, FieldExpression.sub 231 337, FieldExpression.mul 1709 1789, FieldExpression.sub 232 338] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_056 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1792
      ([FieldExpression.mul 1709 1791, FieldExpression.sub 233 339, FieldExpression.mul 1709 1793, FieldExpression.mul 1642 1714, FieldExpression.sub 229 340, FieldExpression.mul 1714 1796, FieldExpression.sub 230 341, FieldExpression.mul 1714 1798, FieldExpression.sub 231 342, FieldExpression.mul 1714 1800, FieldExpression.sub 232 343, FieldExpression.mul 1714 1802, FieldExpression.sub 233 344, FieldExpression.mul 1714 1804, FieldExpression.mul 1648 1719, FieldExpression.sub 229 345, FieldExpression.mul 1719 1807, FieldExpression.sub 230 346, FieldExpression.mul 1719 1809, FieldExpression.sub 231 347, FieldExpression.mul 1719 1811, FieldExpression.sub 232 348, FieldExpression.mul 1719 1813, FieldExpression.sub 233 349, FieldExpression.mul 1719 1815, FieldExpression.mul 1234 1608, FieldExpression.mul 320 1817, FieldExpression.mul 321 1817, FieldExpression.mul 322 1817, FieldExpression.mul 323 1817, FieldExpression.mul 324 1817, FieldExpression.mul 1234 1618] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_057 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1824
      ([FieldExpression.mul 325 1823, FieldExpression.mul 326 1823, FieldExpression.mul 327 1823, FieldExpression.mul 328 1823, FieldExpression.mul 329 1823, FieldExpression.mul 1234 1627, FieldExpression.mul 330 1829, FieldExpression.mul 331 1829, FieldExpression.mul 332 1829, FieldExpression.mul 333 1829, FieldExpression.mul 334 1829, FieldExpression.mul 1234 1635, FieldExpression.mul 335 1835, FieldExpression.mul 336 1835, FieldExpression.mul 337 1835, FieldExpression.mul 338 1835, FieldExpression.mul 339 1835, FieldExpression.mul 1234 1642, FieldExpression.mul 340 1841, FieldExpression.mul 341 1841, FieldExpression.mul 342 1841, FieldExpression.mul 343 1841, FieldExpression.mul 344 1841, FieldExpression.mul 1234 1648, FieldExpression.mul 345 1847, FieldExpression.mul 346 1847, FieldExpression.mul 347 1847, FieldExpression.mul 348 1847, FieldExpression.mul 349 1847, FieldExpression.mul 1493 1617, FieldExpression.sub 320 325, FieldExpression.mul 1234 1853] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_058 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1856
      ([FieldExpression.mul 356 1854, FieldExpression.sub 1856 1, FieldExpression.mul 1855 1857, FieldExpression.sub 1 1853, FieldExpression.mul 1234 1859, FieldExpression.mul 356 1860, FieldExpression.mul 1493 1626, FieldExpression.sub 320 330, FieldExpression.mul 1234 1862, FieldExpression.mul 357 1863, FieldExpression.sub 1865 1, FieldExpression.mul 1864 1866, FieldExpression.sub 1 1862, FieldExpression.mul 1234 1868, FieldExpression.mul 357 1869, FieldExpression.mul 1493 1634, FieldExpression.sub 320 335, FieldExpression.mul 1234 1871, FieldExpression.mul 358 1872, FieldExpression.sub 1874 1, FieldExpression.mul 1873 1875, FieldExpression.sub 1 1871, FieldExpression.mul 1234 1877, FieldExpression.mul 358 1878, FieldExpression.mul 1493 1641, FieldExpression.sub 320 340, FieldExpression.mul 1234 1880, FieldExpression.mul 359 1881, FieldExpression.sub 1883 1, FieldExpression.mul 1882 1884, FieldExpression.sub 1 1880, FieldExpression.mul 1234 1886] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_059 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1888
      ([FieldExpression.mul 359 1887, FieldExpression.mul 305 1493, FieldExpression.sub 320 345, FieldExpression.mul 1234 1889, FieldExpression.mul 360 1890, FieldExpression.sub 1892 1, FieldExpression.mul 1891 1893, FieldExpression.sub 1 1889, FieldExpression.mul 1234 1895, FieldExpression.mul 360 1896, FieldExpression.mul 1617 1626, FieldExpression.sub 325 330, FieldExpression.mul 1234 1898, FieldExpression.mul 361 1899, FieldExpression.sub 1901 1, FieldExpression.mul 1900 1902, FieldExpression.sub 1 1898, FieldExpression.mul 1234 1904, FieldExpression.mul 361 1905, FieldExpression.mul 1617 1634, FieldExpression.sub 325 335, FieldExpression.mul 1234 1907, FieldExpression.mul 362 1908, FieldExpression.sub 1910 1, FieldExpression.mul 1909 1911, FieldExpression.sub 1 1907, FieldExpression.mul 1234 1913, FieldExpression.mul 362 1914, FieldExpression.mul 1617 1641, FieldExpression.sub 325 340, FieldExpression.mul 1234 1916, FieldExpression.mul 363 1917] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_060 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1920
      ([FieldExpression.sub 1919 1, FieldExpression.mul 1918 1920, FieldExpression.sub 1 1916, FieldExpression.mul 1234 1922, FieldExpression.mul 363 1923, FieldExpression.mul 305 1617, FieldExpression.sub 325 345, FieldExpression.mul 1234 1925, FieldExpression.mul 364 1926, FieldExpression.sub 1928 1, FieldExpression.mul 1927 1929, FieldExpression.sub 1 1925, FieldExpression.mul 1234 1931, FieldExpression.mul 364 1932, FieldExpression.mul 1626 1634, FieldExpression.sub 330 335, FieldExpression.mul 1234 1934, FieldExpression.mul 365 1935, FieldExpression.sub 1937 1, FieldExpression.mul 1936 1938, FieldExpression.sub 1 1934, FieldExpression.mul 1234 1940, FieldExpression.mul 365 1941, FieldExpression.mul 1626 1641, FieldExpression.sub 330 340, FieldExpression.mul 1234 1943, FieldExpression.mul 366 1944, FieldExpression.sub 1946 1, FieldExpression.mul 1945 1947, FieldExpression.sub 1 1943, FieldExpression.mul 1234 1949, FieldExpression.mul 366 1950] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_061 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1952
      ([FieldExpression.mul 305 1626, FieldExpression.sub 330 345, FieldExpression.mul 1234 1952, FieldExpression.mul 367 1953, FieldExpression.sub 1955 1, FieldExpression.mul 1954 1956, FieldExpression.sub 1 1952, FieldExpression.mul 1234 1958, FieldExpression.mul 367 1959, FieldExpression.mul 1634 1641, FieldExpression.sub 335 340, FieldExpression.mul 1234 1961, FieldExpression.mul 368 1962, FieldExpression.sub 1964 1, FieldExpression.mul 1963 1965, FieldExpression.sub 1 1961, FieldExpression.mul 1234 1967, FieldExpression.mul 368 1968, FieldExpression.mul 305 1634, FieldExpression.sub 335 345, FieldExpression.mul 1234 1970, FieldExpression.mul 369 1971, FieldExpression.sub 1973 1, FieldExpression.mul 1972 1974, FieldExpression.sub 1 1970, FieldExpression.mul 1234 1976, FieldExpression.mul 369 1977, FieldExpression.mul 305 1641, FieldExpression.sub 340 345, FieldExpression.mul 1234 1979, FieldExpression.mul 370 1980, FieldExpression.sub 1982 1] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_062 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 1984
      ([FieldExpression.mul 1981 1983, FieldExpression.sub 1 1979, FieldExpression.mul 1234 1985, FieldExpression.mul 370 1986, FieldExpression.mul 294 306, FieldExpression.mul 295 1539, FieldExpression.add 1988 1989, FieldExpression.mul 296 1540, FieldExpression.add 1990 1991, FieldExpression.mul 297 1541, FieldExpression.add 1992 1993, FieldExpression.mul 298 1542, FieldExpression.add 1994 1995, FieldExpression.mul 299 1543, FieldExpression.add 1996 1997, FieldExpression.mul 218 1998, FieldExpression.sub 269 255, FieldExpression.mul 218 2000, FieldExpression.sub 270 256, FieldExpression.mul 218 2002, FieldExpression.sub 271 257, FieldExpression.mul 218 2004, FieldExpression.sub 272 258, FieldExpression.mul 218 2006, FieldExpression.sub 273 259, FieldExpression.mul 218 2008, FieldExpression.sub 274 260, FieldExpression.mul 218 2010, FieldExpression.sub 275 261, FieldExpression.mul 218 2012, FieldExpression.mul 218 285, FieldExpression.mul 218 286] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_063 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2016
      ([FieldExpression.mul 218 287, FieldExpression.mul 218 288, FieldExpression.mul 218 289, FieldExpression.mul 218 290, FieldExpression.mul 218 291, FieldExpression.mul 218 292, FieldExpression.mul 218 293, FieldExpression.mul 218 1559, FieldExpression.mul 218 314, FieldExpression.mul 218 315, FieldExpression.mul 218 316, FieldExpression.mul 218 317, FieldExpression.mul 218 318, FieldExpression.mul 218 319, FieldExpression.mul 218 350, FieldExpression.mul 218 351, FieldExpression.mul 218 352, FieldExpression.mul 218 353, FieldExpression.mul 218 354, FieldExpression.mul 218 355, FieldExpression.add 407 408, FieldExpression.add 409 2036, FieldExpression.add 410 2037, FieldExpression.add 407 2038, FieldExpression.add 408 2038, FieldExpression.add 409 2038, FieldExpression.add 410 2038, FieldExpression.add 411 412, FieldExpression.add 413 2043, FieldExpression.add 414 2044, FieldExpression.add 411 2045, FieldExpression.add 412 2045] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_064 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2048
      ([FieldExpression.add 413 2045, FieldExpression.add 414 2045, FieldExpression.add 415 416, FieldExpression.add 417 2050, FieldExpression.add 418 2051, FieldExpression.add 415 2052, FieldExpression.add 416 2052, FieldExpression.add 417 2052, FieldExpression.add 418 2052, FieldExpression.add 419 420, FieldExpression.add 421 2057, FieldExpression.add 422 2058, FieldExpression.add 419 2059, FieldExpression.add 420 2059, FieldExpression.add 421 2059, FieldExpression.add 422 2059, FieldExpression.add 2039 2046, FieldExpression.add 2053 2060, FieldExpression.add 2064 2065, FieldExpression.add 2046 2066, FieldExpression.add 2060 2066, FieldExpression.add 2039 2039, FieldExpression.add 2068 2069, FieldExpression.add 2053 2053, FieldExpression.add 2067 2071, FieldExpression.add 2064 2067, FieldExpression.add 2065 2068, FieldExpression.add 2040 2047, FieldExpression.add 2054 2061, FieldExpression.add 2075 2076, FieldExpression.add 2047 2077, FieldExpression.add 2061 2077] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_065 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2080
      ([FieldExpression.add 2040 2040, FieldExpression.add 2079 2080, FieldExpression.add 2054 2054, FieldExpression.add 2078 2082, FieldExpression.add 2075 2078, FieldExpression.add 2076 2079, FieldExpression.add 2041 2048, FieldExpression.add 2055 2062, FieldExpression.add 2086 2087, FieldExpression.add 2048 2088, FieldExpression.add 2062 2088, FieldExpression.add 2041 2041, FieldExpression.add 2090 2091, FieldExpression.add 2055 2055, FieldExpression.add 2089 2093, FieldExpression.add 2086 2089, FieldExpression.add 2087 2090, FieldExpression.add 2042 2049, FieldExpression.add 2056 2063, FieldExpression.add 2097 2098, FieldExpression.add 2049 2099, FieldExpression.add 2063 2099, FieldExpression.add 2042 2042, FieldExpression.add 2101 2102, FieldExpression.add 2056 2056, FieldExpression.add 2100 2104, FieldExpression.add 2097 2100, FieldExpression.add 2098 2101, FieldExpression.constant 1579613653969377219, FieldExpression.add 2073 2108, FieldExpression.sub 423 2109, FieldExpression.sub 423 2108] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_066 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2112
      ([FieldExpression.constant 15509510893087893340, FieldExpression.add 2084 2112, FieldExpression.sub 424 2113, FieldExpression.sub 424 2112, FieldExpression.constant 10090715174060125222, FieldExpression.add 2095 2116, FieldExpression.sub 425 2117, FieldExpression.sub 425 2116, FieldExpression.constant 5625716564419252202, FieldExpression.add 2106 2120, FieldExpression.sub 426 2121, FieldExpression.sub 426 2120, FieldExpression.constant 3006005019077469174, FieldExpression.add 2072 2124, FieldExpression.sub 427 2125, FieldExpression.sub 427 2124, FieldExpression.constant 18314693207014427912, FieldExpression.add 2083 2128, FieldExpression.sub 428 2129, FieldExpression.sub 428 2128, FieldExpression.constant 10170571510627764565, FieldExpression.add 2094 2132, FieldExpression.sub 429 2133, FieldExpression.sub 429 2132, FieldExpression.constant 2027625550790675754, FieldExpression.add 2105 2136, FieldExpression.sub 430 2137, FieldExpression.sub 430 2136, FieldExpression.constant 3983470257916202094, FieldExpression.add 2074 2140, FieldExpression.sub 431 2141, FieldExpression.sub 431 2140] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_067 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2144
      ([FieldExpression.constant 3423470109396435354, FieldExpression.add 2085 2144, FieldExpression.sub 432 2145, FieldExpression.sub 432 2144, FieldExpression.constant 3450488264035752368, FieldExpression.add 2096 2148, FieldExpression.sub 433 2149, FieldExpression.sub 433 2148, FieldExpression.constant 3151070045406026687, FieldExpression.add 2107 2152, FieldExpression.sub 434 2153, FieldExpression.sub 434 2152, FieldExpression.constant 13462781804006123550, FieldExpression.add 2070 2156, FieldExpression.sub 435 2157, FieldExpression.sub 435 2156, FieldExpression.constant 13288575772684627216, FieldExpression.add 2081 2160, FieldExpression.sub 436 2161, FieldExpression.sub 436 2160, FieldExpression.constant 13745549378090937523, FieldExpression.add 2092 2164, FieldExpression.sub 437 2165, FieldExpression.sub 437 2164, FieldExpression.constant 7780139165529418388, FieldExpression.add 2103 2168, FieldExpression.sub 438 2169, FieldExpression.sub 438 2168, FieldExpression.add 2108 2111, FieldExpression.mul 2172 2172, FieldExpression.mul 2173 2173, FieldExpression.mul 2173 2174] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_068 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2176
      ([FieldExpression.mul 2172 2175, FieldExpression.add 2112 2115, FieldExpression.mul 2177 2177, FieldExpression.mul 2178 2178, FieldExpression.mul 2178 2179, FieldExpression.mul 2177 2180, FieldExpression.add 2116 2119, FieldExpression.mul 2182 2182, FieldExpression.mul 2183 2183, FieldExpression.mul 2183 2184, FieldExpression.mul 2182 2185, FieldExpression.add 2120 2123, FieldExpression.mul 2187 2187, FieldExpression.mul 2188 2188, FieldExpression.mul 2188 2189, FieldExpression.mul 2187 2190, FieldExpression.add 2124 2127, FieldExpression.mul 2192 2192, FieldExpression.mul 2193 2193, FieldExpression.mul 2193 2194, FieldExpression.mul 2192 2195, FieldExpression.add 2128 2131, FieldExpression.mul 2197 2197, FieldExpression.mul 2198 2198, FieldExpression.mul 2198 2199, FieldExpression.mul 2197 2200, FieldExpression.add 2132 2135, FieldExpression.mul 2202 2202, FieldExpression.mul 2203 2203, FieldExpression.mul 2203 2204, FieldExpression.mul 2202 2205, FieldExpression.add 2136 2139] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_069 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2208
      ([FieldExpression.mul 2207 2207, FieldExpression.mul 2208 2208, FieldExpression.mul 2208 2209, FieldExpression.mul 2207 2210, FieldExpression.add 2140 2143, FieldExpression.mul 2212 2212, FieldExpression.mul 2213 2213, FieldExpression.mul 2213 2214, FieldExpression.mul 2212 2215, FieldExpression.add 2144 2147, FieldExpression.mul 2217 2217, FieldExpression.mul 2218 2218, FieldExpression.mul 2218 2219, FieldExpression.mul 2217 2220, FieldExpression.add 2148 2151, FieldExpression.mul 2222 2222, FieldExpression.mul 2223 2223, FieldExpression.mul 2223 2224, FieldExpression.mul 2222 2225, FieldExpression.add 2152 2155, FieldExpression.mul 2227 2227, FieldExpression.mul 2228 2228, FieldExpression.mul 2228 2229, FieldExpression.mul 2227 2230, FieldExpression.add 2156 2159, FieldExpression.mul 2232 2232, FieldExpression.mul 2233 2233, FieldExpression.mul 2233 2234, FieldExpression.mul 2232 2235, FieldExpression.add 2160 2163, FieldExpression.mul 2237 2237, FieldExpression.mul 2238 2238] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_070 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2240
      ([FieldExpression.mul 2238 2239, FieldExpression.mul 2237 2240, FieldExpression.add 2164 2167, FieldExpression.mul 2242 2242, FieldExpression.mul 2243 2243, FieldExpression.mul 2243 2244, FieldExpression.mul 2242 2245, FieldExpression.add 2168 2171, FieldExpression.mul 2247 2247, FieldExpression.mul 2248 2248, FieldExpression.mul 2248 2249, FieldExpression.mul 2247 2250, FieldExpression.add 2176 2181, FieldExpression.add 2186 2252, FieldExpression.add 2191 2253, FieldExpression.add 2176 2254, FieldExpression.add 2181 2254, FieldExpression.add 2186 2254, FieldExpression.add 2191 2254, FieldExpression.add 2196 2201, FieldExpression.add 2206 2259, FieldExpression.add 2211 2260, FieldExpression.add 2196 2261, FieldExpression.add 2201 2261, FieldExpression.add 2206 2261, FieldExpression.add 2211 2261, FieldExpression.add 2216 2221, FieldExpression.add 2226 2266, FieldExpression.add 2231 2267, FieldExpression.add 2216 2268, FieldExpression.add 2221 2268, FieldExpression.add 2226 2268] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_071 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2272
      ([FieldExpression.add 2231 2268, FieldExpression.add 2236 2241, FieldExpression.add 2246 2273, FieldExpression.add 2251 2274, FieldExpression.add 2236 2275, FieldExpression.add 2241 2275, FieldExpression.add 2246 2275, FieldExpression.add 2251 2275, FieldExpression.add 2255 2262, FieldExpression.add 2269 2276, FieldExpression.add 2280 2281, FieldExpression.add 2262 2282, FieldExpression.add 2276 2282, FieldExpression.add 2255 2255, FieldExpression.add 2284 2285, FieldExpression.add 2269 2269, FieldExpression.add 2283 2287, FieldExpression.add 2280 2283, FieldExpression.add 2281 2284, FieldExpression.add 2256 2263, FieldExpression.add 2270 2277, FieldExpression.add 2291 2292, FieldExpression.add 2263 2293, FieldExpression.add 2277 2293, FieldExpression.add 2256 2256, FieldExpression.add 2295 2296, FieldExpression.add 2270 2270, FieldExpression.add 2294 2298, FieldExpression.add 2291 2294, FieldExpression.add 2292 2295, FieldExpression.add 2257 2264, FieldExpression.add 2271 2278] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_072 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2304
      ([FieldExpression.add 2302 2303, FieldExpression.add 2264 2304, FieldExpression.add 2278 2304, FieldExpression.add 2257 2257, FieldExpression.add 2306 2307, FieldExpression.add 2271 2271, FieldExpression.add 2305 2309, FieldExpression.add 2302 2305, FieldExpression.add 2303 2306, FieldExpression.add 2258 2265, FieldExpression.add 2272 2279, FieldExpression.add 2313 2314, FieldExpression.add 2265 2315, FieldExpression.add 2279 2315, FieldExpression.add 2258 2258, FieldExpression.add 2317 2318, FieldExpression.add 2272 2272, FieldExpression.add 2316 2320, FieldExpression.add 2313 2316, FieldExpression.add 2314 2317, FieldExpression.constant 11699769881923825909, FieldExpression.add 2289 2324, FieldExpression.sub 439 2325, FieldExpression.sub 439 2324, FieldExpression.constant 4349260652212695338, FieldExpression.add 2300 2328, FieldExpression.sub 440 2329, FieldExpression.sub 440 2328, FieldExpression.constant 8228348357294662898, FieldExpression.add 2311 2332, FieldExpression.sub 441 2333, FieldExpression.sub 441 2332] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_073 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2336
      ([FieldExpression.constant 12037145371429260559, FieldExpression.add 2322 2336, FieldExpression.sub 442 2337, FieldExpression.sub 442 2336, FieldExpression.constant 7743383997471469184, FieldExpression.add 2288 2340, FieldExpression.sub 443 2341, FieldExpression.sub 443 2340, FieldExpression.constant 7842006993218978420, FieldExpression.add 2299 2344, FieldExpression.sub 444 2345, FieldExpression.sub 444 2344, FieldExpression.constant 18369471830829996810, FieldExpression.add 2310 2348, FieldExpression.sub 445 2349, FieldExpression.sub 445 2348, FieldExpression.constant 10157815501749214163, FieldExpression.add 2321 2352, FieldExpression.sub 446 2353, FieldExpression.sub 446 2352, FieldExpression.constant 11128005290408113568, FieldExpression.add 2290 2356, FieldExpression.sub 447 2357, FieldExpression.sub 447 2356, FieldExpression.constant 12272917402811871099, FieldExpression.add 2301 2360, FieldExpression.sub 448 2361, FieldExpression.sub 448 2360, FieldExpression.constant 106820976709770637, FieldExpression.add 2312 2364, FieldExpression.sub 449 2365, FieldExpression.sub 449 2364] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_074 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2368
      ([FieldExpression.constant 6178857985076893256, FieldExpression.add 2323 2368, FieldExpression.sub 450 2369, FieldExpression.sub 450 2368, FieldExpression.constant 14036787039817180193, FieldExpression.add 2286 2372, FieldExpression.sub 451 2373, FieldExpression.sub 451 2372, FieldExpression.constant 1659458828486927362, FieldExpression.add 2297 2376, FieldExpression.sub 452 2377, FieldExpression.sub 452 2376, FieldExpression.constant 15938183887757779615, FieldExpression.add 2308 2380, FieldExpression.sub 453 2381, FieldExpression.sub 453 2380, FieldExpression.constant 10060334973073197601, FieldExpression.add 2319 2384, FieldExpression.sub 454 2385, FieldExpression.sub 454 2384, FieldExpression.add 2324 2327, FieldExpression.mul 2388 2388, FieldExpression.mul 2389 2389, FieldExpression.mul 2389 2390, FieldExpression.mul 2388 2391, FieldExpression.add 2328 2331, FieldExpression.mul 2393 2393, FieldExpression.mul 2394 2394, FieldExpression.mul 2394 2395, FieldExpression.mul 2393 2396, FieldExpression.add 2332 2335, FieldExpression.mul 2398 2398] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_075 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2400
      ([FieldExpression.mul 2399 2399, FieldExpression.mul 2399 2400, FieldExpression.mul 2398 2401, FieldExpression.add 2336 2339, FieldExpression.mul 2403 2403, FieldExpression.mul 2404 2404, FieldExpression.mul 2404 2405, FieldExpression.mul 2403 2406, FieldExpression.add 2340 2343, FieldExpression.mul 2408 2408, FieldExpression.mul 2409 2409, FieldExpression.mul 2409 2410, FieldExpression.mul 2408 2411, FieldExpression.add 2344 2347, FieldExpression.mul 2413 2413, FieldExpression.mul 2414 2414, FieldExpression.mul 2414 2415, FieldExpression.mul 2413 2416, FieldExpression.add 2348 2351, FieldExpression.mul 2418 2418, FieldExpression.mul 2419 2419, FieldExpression.mul 2419 2420, FieldExpression.mul 2418 2421, FieldExpression.add 2352 2355, FieldExpression.mul 2423 2423, FieldExpression.mul 2424 2424, FieldExpression.mul 2424 2425, FieldExpression.mul 2423 2426, FieldExpression.add 2356 2359, FieldExpression.mul 2428 2428, FieldExpression.mul 2429 2429, FieldExpression.mul 2429 2430] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_076 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2432
      ([FieldExpression.mul 2428 2431, FieldExpression.add 2360 2363, FieldExpression.mul 2433 2433, FieldExpression.mul 2434 2434, FieldExpression.mul 2434 2435, FieldExpression.mul 2433 2436, FieldExpression.add 2364 2367, FieldExpression.mul 2438 2438, FieldExpression.mul 2439 2439, FieldExpression.mul 2439 2440, FieldExpression.mul 2438 2441, FieldExpression.add 2368 2371, FieldExpression.mul 2443 2443, FieldExpression.mul 2444 2444, FieldExpression.mul 2444 2445, FieldExpression.mul 2443 2446, FieldExpression.add 2372 2375, FieldExpression.mul 2448 2448, FieldExpression.mul 2449 2449, FieldExpression.mul 2449 2450, FieldExpression.mul 2448 2451, FieldExpression.add 2376 2379, FieldExpression.mul 2453 2453, FieldExpression.mul 2454 2454, FieldExpression.mul 2454 2455, FieldExpression.mul 2453 2456, FieldExpression.add 2380 2383, FieldExpression.mul 2458 2458, FieldExpression.mul 2459 2459, FieldExpression.mul 2459 2460, FieldExpression.mul 2458 2461, FieldExpression.add 2384 2387] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_077 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2464
      ([FieldExpression.mul 2463 2463, FieldExpression.mul 2464 2464, FieldExpression.mul 2464 2465, FieldExpression.mul 2463 2466, FieldExpression.add 2392 2397, FieldExpression.add 2402 2468, FieldExpression.add 2407 2469, FieldExpression.add 2392 2470, FieldExpression.add 2397 2470, FieldExpression.add 2402 2470, FieldExpression.add 2407 2470, FieldExpression.add 2412 2417, FieldExpression.add 2422 2475, FieldExpression.add 2427 2476, FieldExpression.add 2412 2477, FieldExpression.add 2417 2477, FieldExpression.add 2422 2477, FieldExpression.add 2427 2477, FieldExpression.add 2432 2437, FieldExpression.add 2442 2482, FieldExpression.add 2447 2483, FieldExpression.add 2432 2484, FieldExpression.add 2437 2484, FieldExpression.add 2442 2484, FieldExpression.add 2447 2484, FieldExpression.add 2452 2457, FieldExpression.add 2462 2489, FieldExpression.add 2467 2490, FieldExpression.add 2452 2491, FieldExpression.add 2457 2491, FieldExpression.add 2462 2491, FieldExpression.add 2467 2491] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_078 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2496
      ([FieldExpression.add 2471 2478, FieldExpression.add 2485 2492, FieldExpression.add 2496 2497, FieldExpression.add 2478 2498, FieldExpression.add 2492 2498, FieldExpression.add 2471 2471, FieldExpression.add 2500 2501, FieldExpression.add 2485 2485, FieldExpression.add 2499 2503, FieldExpression.add 2496 2499, FieldExpression.add 2497 2500, FieldExpression.add 2472 2479, FieldExpression.add 2486 2493, FieldExpression.add 2507 2508, FieldExpression.add 2479 2509, FieldExpression.add 2493 2509, FieldExpression.add 2472 2472, FieldExpression.add 2511 2512, FieldExpression.add 2486 2486, FieldExpression.add 2510 2514, FieldExpression.add 2507 2510, FieldExpression.add 2508 2511, FieldExpression.add 2473 2480, FieldExpression.add 2487 2494, FieldExpression.add 2518 2519, FieldExpression.add 2480 2520, FieldExpression.add 2494 2520, FieldExpression.add 2473 2473, FieldExpression.add 2522 2523, FieldExpression.add 2487 2487, FieldExpression.add 2521 2525, FieldExpression.add 2518 2521] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_079 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2528
      ([FieldExpression.add 2519 2522, FieldExpression.add 2474 2481, FieldExpression.add 2488 2495, FieldExpression.add 2529 2530, FieldExpression.add 2481 2531, FieldExpression.add 2495 2531, FieldExpression.add 2474 2474, FieldExpression.add 2533 2534, FieldExpression.add 2488 2488, FieldExpression.add 2532 2536, FieldExpression.add 2529 2532, FieldExpression.add 2530 2533, FieldExpression.constant 12437259172286625042, FieldExpression.add 2505 2540, FieldExpression.sub 455 2541, FieldExpression.sub 455 2540, FieldExpression.constant 3143835545170851304, FieldExpression.add 2516 2544, FieldExpression.sub 456 2545, FieldExpression.sub 456 2544, FieldExpression.constant 14361575850007152549, FieldExpression.add 2527 2548, FieldExpression.sub 457 2549, FieldExpression.sub 457 2548, FieldExpression.constant 11810209965918630788, FieldExpression.add 2538 2552, FieldExpression.sub 458 2553, FieldExpression.sub 458 2552, FieldExpression.constant 17667700303515849362, FieldExpression.add 2504 2556, FieldExpression.sub 459 2557, FieldExpression.sub 459 2556] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_080 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2560
      ([FieldExpression.constant 13451932870729425780, FieldExpression.add 2515 2560, FieldExpression.sub 460 2561, FieldExpression.sub 460 2560, FieldExpression.constant 17496644301504593329, FieldExpression.add 2526 2564, FieldExpression.sub 461 2565, FieldExpression.sub 461 2564, FieldExpression.constant 1778669202480014256, FieldExpression.add 2537 2568, FieldExpression.sub 462 2569, FieldExpression.sub 462 2568, FieldExpression.constant 11124488067381312952, FieldExpression.add 2506 2572, FieldExpression.sub 463 2573, FieldExpression.sub 463 2572, FieldExpression.constant 14273583775934080755, FieldExpression.add 2517 2576, FieldExpression.sub 464 2577, FieldExpression.sub 464 2576, FieldExpression.constant 13257379154210125715, FieldExpression.add 2528 2580, FieldExpression.sub 465 2581, FieldExpression.sub 465 2580, FieldExpression.constant 15182093233826554989, FieldExpression.add 2539 2584, FieldExpression.sub 466 2585, FieldExpression.sub 466 2584, FieldExpression.constant 5343815959848316783, FieldExpression.add 2502 2588, FieldExpression.sub 467 2589, FieldExpression.sub 467 2588] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_081 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2592
      ([FieldExpression.constant 5696193414571279556, FieldExpression.add 2513 2592, FieldExpression.sub 468 2593, FieldExpression.sub 468 2592, FieldExpression.constant 6089787229781325813, FieldExpression.add 2524 2596, FieldExpression.sub 469 2597, FieldExpression.sub 469 2596, FieldExpression.constant 3717595218375990594, FieldExpression.add 2535 2600, FieldExpression.sub 470 2601, FieldExpression.sub 470 2600, FieldExpression.add 2540 2543, FieldExpression.mul 2604 2604, FieldExpression.mul 2605 2605, FieldExpression.mul 2605 2606, FieldExpression.mul 2604 2607, FieldExpression.add 2544 2547, FieldExpression.mul 2609 2609, FieldExpression.mul 2610 2610, FieldExpression.mul 2610 2611, FieldExpression.mul 2609 2612, FieldExpression.add 2548 2551, FieldExpression.mul 2614 2614, FieldExpression.mul 2615 2615, FieldExpression.mul 2615 2616, FieldExpression.mul 2614 2617, FieldExpression.add 2552 2555, FieldExpression.mul 2619 2619, FieldExpression.mul 2620 2620, FieldExpression.mul 2620 2621, FieldExpression.mul 2619 2622] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_082 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2624
      ([FieldExpression.add 2556 2559, FieldExpression.mul 2624 2624, FieldExpression.mul 2625 2625, FieldExpression.mul 2625 2626, FieldExpression.mul 2624 2627, FieldExpression.add 2560 2563, FieldExpression.mul 2629 2629, FieldExpression.mul 2630 2630, FieldExpression.mul 2630 2631, FieldExpression.mul 2629 2632, FieldExpression.add 2564 2567, FieldExpression.mul 2634 2634, FieldExpression.mul 2635 2635, FieldExpression.mul 2635 2636, FieldExpression.mul 2634 2637, FieldExpression.add 2568 2571, FieldExpression.mul 2639 2639, FieldExpression.mul 2640 2640, FieldExpression.mul 2640 2641, FieldExpression.mul 2639 2642, FieldExpression.add 2572 2575, FieldExpression.mul 2644 2644, FieldExpression.mul 2645 2645, FieldExpression.mul 2645 2646, FieldExpression.mul 2644 2647, FieldExpression.add 2576 2579, FieldExpression.mul 2649 2649, FieldExpression.mul 2650 2650, FieldExpression.mul 2650 2651, FieldExpression.mul 2649 2652, FieldExpression.add 2580 2583, FieldExpression.mul 2654 2654] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_083 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2656
      ([FieldExpression.mul 2655 2655, FieldExpression.mul 2655 2656, FieldExpression.mul 2654 2657, FieldExpression.add 2584 2587, FieldExpression.mul 2659 2659, FieldExpression.mul 2660 2660, FieldExpression.mul 2660 2661, FieldExpression.mul 2659 2662, FieldExpression.add 2588 2591, FieldExpression.mul 2664 2664, FieldExpression.mul 2665 2665, FieldExpression.mul 2665 2666, FieldExpression.mul 2664 2667, FieldExpression.add 2592 2595, FieldExpression.mul 2669 2669, FieldExpression.mul 2670 2670, FieldExpression.mul 2670 2671, FieldExpression.mul 2669 2672, FieldExpression.add 2596 2599, FieldExpression.mul 2674 2674, FieldExpression.mul 2675 2675, FieldExpression.mul 2675 2676, FieldExpression.mul 2674 2677, FieldExpression.add 2600 2603, FieldExpression.mul 2679 2679, FieldExpression.mul 2680 2680, FieldExpression.mul 2680 2681, FieldExpression.mul 2679 2682, FieldExpression.add 2608 2613, FieldExpression.add 2618 2684, FieldExpression.add 2623 2685, FieldExpression.add 2608 2686] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_084 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2688
      ([FieldExpression.add 2613 2686, FieldExpression.add 2618 2686, FieldExpression.add 2623 2686, FieldExpression.add 2628 2633, FieldExpression.add 2638 2691, FieldExpression.add 2643 2692, FieldExpression.add 2628 2693, FieldExpression.add 2633 2693, FieldExpression.add 2638 2693, FieldExpression.add 2643 2693, FieldExpression.add 2648 2653, FieldExpression.add 2658 2698, FieldExpression.add 2663 2699, FieldExpression.add 2648 2700, FieldExpression.add 2653 2700, FieldExpression.add 2658 2700, FieldExpression.add 2663 2700, FieldExpression.add 2668 2673, FieldExpression.add 2678 2705, FieldExpression.add 2683 2706, FieldExpression.add 2668 2707, FieldExpression.add 2673 2707, FieldExpression.add 2678 2707, FieldExpression.add 2683 2707, FieldExpression.add 2687 2694, FieldExpression.add 2701 2708, FieldExpression.add 2712 2713, FieldExpression.add 2694 2714, FieldExpression.add 2708 2714, FieldExpression.add 2687 2687, FieldExpression.add 2716 2717, FieldExpression.add 2701 2701] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_085 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2720
      ([FieldExpression.add 2715 2719, FieldExpression.add 2712 2715, FieldExpression.add 2713 2716, FieldExpression.add 2688 2695, FieldExpression.add 2702 2709, FieldExpression.add 2723 2724, FieldExpression.add 2695 2725, FieldExpression.add 2709 2725, FieldExpression.add 2688 2688, FieldExpression.add 2727 2728, FieldExpression.add 2702 2702, FieldExpression.add 2726 2730, FieldExpression.add 2723 2726, FieldExpression.add 2724 2727, FieldExpression.add 2689 2696, FieldExpression.add 2703 2710, FieldExpression.add 2734 2735, FieldExpression.add 2696 2736, FieldExpression.add 2710 2736, FieldExpression.add 2689 2689, FieldExpression.add 2738 2739, FieldExpression.add 2703 2703, FieldExpression.add 2737 2741, FieldExpression.add 2734 2737, FieldExpression.add 2735 2738, FieldExpression.add 2690 2697, FieldExpression.add 2704 2711, FieldExpression.add 2745 2746, FieldExpression.add 2697 2747, FieldExpression.add 2711 2747, FieldExpression.add 2690 2690, FieldExpression.add 2749 2750] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_086 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2752
      ([FieldExpression.add 2704 2704, FieldExpression.add 2748 2752, FieldExpression.add 2745 2748, FieldExpression.add 2746 2749, FieldExpression.constant 12355842859741995537, FieldExpression.add 2721 2756, FieldExpression.sub 471 2757, FieldExpression.sub 471 2756, FieldExpression.constant 14160921043125059199, FieldExpression.add 2732 2760, FieldExpression.sub 472 2761, FieldExpression.sub 472 2760, FieldExpression.constant 13682913322779819091, FieldExpression.add 2743 2764, FieldExpression.sub 473 2765, FieldExpression.sub 473 2764, FieldExpression.constant 12343504462597575239, FieldExpression.add 2754 2768, FieldExpression.sub 474 2769, FieldExpression.sub 474 2768, FieldExpression.constant 14249643564311509087, FieldExpression.add 2720 2772, FieldExpression.sub 475 2773, FieldExpression.sub 475 2772, FieldExpression.constant 15849758561085927402, FieldExpression.add 2731 2776, FieldExpression.sub 476 2777, FieldExpression.sub 476 2776, FieldExpression.constant 12186564686511703262, FieldExpression.add 2742 2780, FieldExpression.sub 477 2781, FieldExpression.sub 477 2780] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_087 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2784
      ([FieldExpression.constant 690520822232718983, FieldExpression.add 2753 2784, FieldExpression.sub 478 2785, FieldExpression.sub 478 2784, FieldExpression.constant 684200944081655198, FieldExpression.add 2722 2788, FieldExpression.sub 479 2789, FieldExpression.sub 479 2788, FieldExpression.constant 6008958449718781068, FieldExpression.add 2733 2792, FieldExpression.sub 480 2793, FieldExpression.sub 480 2792, FieldExpression.constant 3098079696536837500, FieldExpression.add 2744 2796, FieldExpression.sub 481 2797, FieldExpression.sub 481 2796, FieldExpression.constant 12083506578988585239, FieldExpression.add 2755 2800, FieldExpression.sub 482 2801, FieldExpression.sub 482 2800, FieldExpression.constant 6489163969976034646, FieldExpression.add 2718 2804, FieldExpression.sub 483 2805, FieldExpression.sub 483 2804, FieldExpression.constant 1186411428667285248, FieldExpression.add 2729 2808, FieldExpression.sub 484 2809, FieldExpression.sub 484 2808, FieldExpression.constant 11192474480021157091, FieldExpression.add 2740 2812, FieldExpression.sub 485 2813, FieldExpression.sub 485 2812] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_088 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2816
      ([FieldExpression.constant 17095617549195818058, FieldExpression.add 2751 2816, FieldExpression.sub 486 2817, FieldExpression.sub 486 2816, FieldExpression.add 2756 2759, FieldExpression.mul 2820 2820, FieldExpression.mul 2821 2821, FieldExpression.mul 2821 2822, FieldExpression.mul 2820 2823, FieldExpression.add 2760 2763, FieldExpression.mul 2825 2825, FieldExpression.mul 2826 2826, FieldExpression.mul 2826 2827, FieldExpression.mul 2825 2828, FieldExpression.add 2764 2767, FieldExpression.mul 2830 2830, FieldExpression.mul 2831 2831, FieldExpression.mul 2831 2832, FieldExpression.mul 2830 2833, FieldExpression.add 2768 2771, FieldExpression.mul 2835 2835, FieldExpression.mul 2836 2836, FieldExpression.mul 2836 2837, FieldExpression.mul 2835 2838, FieldExpression.add 2772 2775, FieldExpression.mul 2840 2840, FieldExpression.mul 2841 2841, FieldExpression.mul 2841 2842, FieldExpression.mul 2840 2843, FieldExpression.add 2776 2779, FieldExpression.mul 2845 2845, FieldExpression.mul 2846 2846] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_089 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2848
      ([FieldExpression.mul 2846 2847, FieldExpression.mul 2845 2848, FieldExpression.add 2780 2783, FieldExpression.mul 2850 2850, FieldExpression.mul 2851 2851, FieldExpression.mul 2851 2852, FieldExpression.mul 2850 2853, FieldExpression.add 2784 2787, FieldExpression.mul 2855 2855, FieldExpression.mul 2856 2856, FieldExpression.mul 2856 2857, FieldExpression.mul 2855 2858, FieldExpression.add 2788 2791, FieldExpression.mul 2860 2860, FieldExpression.mul 2861 2861, FieldExpression.mul 2861 2862, FieldExpression.mul 2860 2863, FieldExpression.add 2792 2795, FieldExpression.mul 2865 2865, FieldExpression.mul 2866 2866, FieldExpression.mul 2866 2867, FieldExpression.mul 2865 2868, FieldExpression.add 2796 2799, FieldExpression.mul 2870 2870, FieldExpression.mul 2871 2871, FieldExpression.mul 2871 2872, FieldExpression.mul 2870 2873, FieldExpression.add 2800 2803, FieldExpression.mul 2875 2875, FieldExpression.mul 2876 2876, FieldExpression.mul 2876 2877, FieldExpression.mul 2875 2878] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_090 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2880
      ([FieldExpression.add 2804 2807, FieldExpression.mul 2880 2880, FieldExpression.mul 2881 2881, FieldExpression.mul 2881 2882, FieldExpression.mul 2880 2883, FieldExpression.add 2808 2811, FieldExpression.mul 2885 2885, FieldExpression.mul 2886 2886, FieldExpression.mul 2886 2887, FieldExpression.mul 2885 2888, FieldExpression.add 2812 2815, FieldExpression.mul 2890 2890, FieldExpression.mul 2891 2891, FieldExpression.mul 2891 2892, FieldExpression.mul 2890 2893, FieldExpression.add 2816 2819, FieldExpression.mul 2895 2895, FieldExpression.mul 2896 2896, FieldExpression.mul 2896 2897, FieldExpression.mul 2895 2898, FieldExpression.add 2824 2829, FieldExpression.add 2834 2900, FieldExpression.add 2839 2901, FieldExpression.add 2824 2902, FieldExpression.add 2829 2902, FieldExpression.add 2834 2902, FieldExpression.add 2839 2902, FieldExpression.add 2844 2849, FieldExpression.add 2854 2907, FieldExpression.add 2859 2908, FieldExpression.add 2844 2909, FieldExpression.add 2849 2909] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_091 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2912
      ([FieldExpression.add 2854 2909, FieldExpression.add 2859 2909, FieldExpression.add 2864 2869, FieldExpression.add 2874 2914, FieldExpression.add 2879 2915, FieldExpression.add 2864 2916, FieldExpression.add 2869 2916, FieldExpression.add 2874 2916, FieldExpression.add 2879 2916, FieldExpression.add 2884 2889, FieldExpression.add 2894 2921, FieldExpression.add 2899 2922, FieldExpression.add 2884 2923, FieldExpression.add 2889 2923, FieldExpression.add 2894 2923, FieldExpression.add 2899 2923, FieldExpression.add 2903 2910, FieldExpression.add 2917 2924, FieldExpression.add 2928 2929, FieldExpression.add 2910 2930, FieldExpression.add 2924 2930, FieldExpression.add 2903 2903, FieldExpression.add 2932 2933, FieldExpression.add 2917 2917, FieldExpression.add 2931 2935, FieldExpression.add 2928 2931, FieldExpression.add 2929 2932, FieldExpression.add 2904 2911, FieldExpression.add 2918 2925, FieldExpression.add 2939 2940, FieldExpression.add 2911 2941, FieldExpression.add 2925 2941] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_092 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2944
      ([FieldExpression.add 2904 2904, FieldExpression.add 2943 2944, FieldExpression.add 2918 2918, FieldExpression.add 2942 2946, FieldExpression.add 2939 2942, FieldExpression.add 2940 2943, FieldExpression.add 2905 2912, FieldExpression.add 2919 2926, FieldExpression.add 2950 2951, FieldExpression.add 2912 2952, FieldExpression.add 2926 2952, FieldExpression.add 2905 2905, FieldExpression.add 2954 2955, FieldExpression.add 2919 2919, FieldExpression.add 2953 2957, FieldExpression.add 2950 2953, FieldExpression.add 2951 2954, FieldExpression.add 2906 2913, FieldExpression.add 2920 2927, FieldExpression.add 2961 2962, FieldExpression.add 2913 2963, FieldExpression.add 2927 2963, FieldExpression.add 2906 2906, FieldExpression.add 2965 2966, FieldExpression.add 2920 2920, FieldExpression.add 2964 2968, FieldExpression.add 2961 2964, FieldExpression.add 2962 2965, FieldExpression.constant 2949845317987848448, FieldExpression.add 2937 2972, FieldExpression.sub 487 2973, FieldExpression.sub 487 2972] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_093 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 2976
      ([FieldExpression.add 2972 2975, FieldExpression.mul 2976 2976, FieldExpression.mul 2977 2977, FieldExpression.mul 2977 2978, FieldExpression.mul 2976 2979, FieldExpression.add 2948 2980, FieldExpression.add 2959 2981, FieldExpression.add 2970 2982, FieldExpression.add 2936 2983, FieldExpression.add 2947 2984, FieldExpression.add 2958 2985, FieldExpression.add 2969 2986, FieldExpression.add 2938 2987, FieldExpression.add 2949 2988, FieldExpression.add 2960 2989, FieldExpression.add 2971 2990, FieldExpression.add 2934 2991, FieldExpression.add 2945 2992, FieldExpression.add 2956 2993, FieldExpression.add 2967 2994, FieldExpression.constant 16040574633112940480, FieldExpression.mul 2980 2996, FieldExpression.add 2995 2997, FieldExpression.constant 14263299814608977431, FieldExpression.mul 2948 2999, FieldExpression.add 2995 3000, FieldExpression.constant 770395855193680981, FieldExpression.mul 2959 3002, FieldExpression.add 2995 3003, FieldExpression.constant 3459277367440070515, FieldExpression.mul 2970 3005, FieldExpression.add 2995 3006] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_094 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3008
      ([FieldExpression.constant 17087697094293314027, FieldExpression.mul 2936 3008, FieldExpression.add 2995 3009, FieldExpression.constant 6694380135428747348, FieldExpression.mul 2947 3011, FieldExpression.add 2995 3012, FieldExpression.constant 2034408310088972836, FieldExpression.mul 2958 3014, FieldExpression.add 2995 3015, FieldExpression.constant 3434575637390274478, FieldExpression.mul 2969 3017, FieldExpression.add 2995 3018, FieldExpression.constant 6052753985947965968, FieldExpression.mul 2938 3020, FieldExpression.add 2995 3021, FieldExpression.constant 13608362914817483670, FieldExpression.mul 2949 3023, FieldExpression.add 2995 3024, FieldExpression.constant 18163707672964630459, FieldExpression.mul 2960 3026, FieldExpression.add 2995 3027, FieldExpression.constant 14373610220374016704, FieldExpression.mul 2971 3029, FieldExpression.add 2995 3030, FieldExpression.constant 6226282807566121054, FieldExpression.mul 2934 3032, FieldExpression.add 2995 3033, FieldExpression.constant 3643354756180461803, FieldExpression.mul 2945 3035, FieldExpression.add 2995 3036, FieldExpression.constant 13046961313070095543, FieldExpression.mul 2956 3038] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_095 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3040
      ([FieldExpression.add 2995 3039, FieldExpression.constant 8594143216561850811, FieldExpression.mul 2967 3041, FieldExpression.add 2995 3042, FieldExpression.constant 6935557324168256069, FieldExpression.add 2998 3044, FieldExpression.sub 488 3045, FieldExpression.sub 488 3044, FieldExpression.add 3044 3047, FieldExpression.mul 3048 3048, FieldExpression.mul 3049 3049, FieldExpression.mul 3049 3050, FieldExpression.mul 3048 3051, FieldExpression.add 3001 3052, FieldExpression.add 3004 3053, FieldExpression.add 3007 3054, FieldExpression.add 3010 3055, FieldExpression.add 3013 3056, FieldExpression.add 3016 3057, FieldExpression.add 3019 3058, FieldExpression.add 3022 3059, FieldExpression.add 3025 3060, FieldExpression.add 3028 3061, FieldExpression.add 3031 3062, FieldExpression.add 3034 3063, FieldExpression.add 3037 3064, FieldExpression.add 3040 3065, FieldExpression.add 3043 3066, FieldExpression.mul 2996 3052, FieldExpression.add 3067 3068, FieldExpression.mul 2999 3001, FieldExpression.add 3067 3070] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_096 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3072
      ([FieldExpression.mul 3002 3004, FieldExpression.add 3067 3072, FieldExpression.mul 3005 3007, FieldExpression.add 3067 3074, FieldExpression.mul 3008 3010, FieldExpression.add 3067 3076, FieldExpression.mul 3011 3013, FieldExpression.add 3067 3078, FieldExpression.mul 3014 3016, FieldExpression.add 3067 3080, FieldExpression.mul 3017 3019, FieldExpression.add 3067 3082, FieldExpression.mul 3020 3022, FieldExpression.add 3067 3084, FieldExpression.mul 3023 3025, FieldExpression.add 3067 3086, FieldExpression.mul 3026 3028, FieldExpression.add 3067 3088, FieldExpression.mul 3029 3031, FieldExpression.add 3067 3090, FieldExpression.mul 3032 3034, FieldExpression.add 3067 3092, FieldExpression.mul 3035 3037, FieldExpression.add 3067 3094, FieldExpression.mul 3038 3040, FieldExpression.add 3067 3096, FieldExpression.mul 3041 3043, FieldExpression.add 3067 3098, FieldExpression.constant 2055390472619727748, FieldExpression.add 3069 3100, FieldExpression.sub 489 3101, FieldExpression.sub 489 3100] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_097 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3104
      ([FieldExpression.add 3100 3103, FieldExpression.mul 3104 3104, FieldExpression.mul 3105 3105, FieldExpression.mul 3105 3106, FieldExpression.mul 3104 3107, FieldExpression.add 3071 3108, FieldExpression.add 3073 3109, FieldExpression.add 3075 3110, FieldExpression.add 3077 3111, FieldExpression.add 3079 3112, FieldExpression.add 3081 3113, FieldExpression.add 3083 3114, FieldExpression.add 3085 3115, FieldExpression.add 3087 3116, FieldExpression.add 3089 3117, FieldExpression.add 3091 3118, FieldExpression.add 3093 3119, FieldExpression.add 3095 3120, FieldExpression.add 3097 3121, FieldExpression.add 3099 3122, FieldExpression.mul 2996 3108, FieldExpression.add 3123 3124, FieldExpression.mul 2999 3071, FieldExpression.add 3123 3126, FieldExpression.mul 3002 3073, FieldExpression.add 3123 3128, FieldExpression.mul 3005 3075, FieldExpression.add 3123 3130, FieldExpression.mul 3008 3077, FieldExpression.add 3123 3132, FieldExpression.mul 3011 3079, FieldExpression.add 3123 3134] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_098 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3136
      ([FieldExpression.mul 3014 3081, FieldExpression.add 3123 3136, FieldExpression.mul 3017 3083, FieldExpression.add 3123 3138, FieldExpression.mul 3020 3085, FieldExpression.add 3123 3140, FieldExpression.mul 3023 3087, FieldExpression.add 3123 3142, FieldExpression.mul 3026 3089, FieldExpression.add 3123 3144, FieldExpression.mul 3029 3091, FieldExpression.add 3123 3146, FieldExpression.mul 3032 3093, FieldExpression.add 3123 3148, FieldExpression.mul 3035 3095, FieldExpression.add 3123 3150, FieldExpression.mul 3038 3097, FieldExpression.add 3123 3152, FieldExpression.mul 3041 3099, FieldExpression.add 3123 3154, FieldExpression.constant 12399309956582731760, FieldExpression.add 3125 3156, FieldExpression.sub 490 3157, FieldExpression.sub 490 3156, FieldExpression.add 3156 3159, FieldExpression.mul 3160 3160, FieldExpression.mul 3161 3161, FieldExpression.mul 3161 3162, FieldExpression.mul 3160 3163, FieldExpression.add 3127 3164, FieldExpression.add 3129 3165, FieldExpression.add 3131 3166] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_099 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3168
      ([FieldExpression.add 3133 3167, FieldExpression.add 3135 3168, FieldExpression.add 3137 3169, FieldExpression.add 3139 3170, FieldExpression.add 3141 3171, FieldExpression.add 3143 3172, FieldExpression.add 3145 3173, FieldExpression.add 3147 3174, FieldExpression.add 3149 3175, FieldExpression.add 3151 3176, FieldExpression.add 3153 3177, FieldExpression.add 3155 3178, FieldExpression.mul 2996 3164, FieldExpression.add 3179 3180, FieldExpression.mul 2999 3127, FieldExpression.add 3179 3182, FieldExpression.mul 3002 3129, FieldExpression.add 3179 3184, FieldExpression.mul 3005 3131, FieldExpression.add 3179 3186, FieldExpression.mul 3008 3133, FieldExpression.add 3179 3188, FieldExpression.mul 3011 3135, FieldExpression.add 3179 3190, FieldExpression.mul 3014 3137, FieldExpression.add 3179 3192, FieldExpression.mul 3017 3139, FieldExpression.add 3179 3194, FieldExpression.mul 3020 3141, FieldExpression.add 3179 3196, FieldExpression.mul 3023 3143, FieldExpression.add 3179 3198] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_100 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3200
      ([FieldExpression.mul 3026 3145, FieldExpression.add 3179 3200, FieldExpression.mul 3029 3147, FieldExpression.add 3179 3202, FieldExpression.mul 3032 3149, FieldExpression.add 3179 3204, FieldExpression.mul 3035 3151, FieldExpression.add 3179 3206, FieldExpression.mul 3038 3153, FieldExpression.add 3179 3208, FieldExpression.mul 3041 3155, FieldExpression.add 3179 3210, FieldExpression.constant 3088058410657255303, FieldExpression.add 3181 3212, FieldExpression.sub 491 3213, FieldExpression.sub 491 3212, FieldExpression.add 3212 3215, FieldExpression.mul 3216 3216, FieldExpression.mul 3217 3217, FieldExpression.mul 3217 3218, FieldExpression.mul 3216 3219, FieldExpression.add 3183 3220, FieldExpression.add 3185 3221, FieldExpression.add 3187 3222, FieldExpression.add 3189 3223, FieldExpression.add 3191 3224, FieldExpression.add 3193 3225, FieldExpression.add 3195 3226, FieldExpression.add 3197 3227, FieldExpression.add 3199 3228, FieldExpression.add 3201 3229, FieldExpression.add 3203 3230] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_101 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3232
      ([FieldExpression.add 3205 3231, FieldExpression.add 3207 3232, FieldExpression.add 3209 3233, FieldExpression.add 3211 3234, FieldExpression.mul 2996 3220, FieldExpression.add 3235 3236, FieldExpression.mul 2999 3183, FieldExpression.add 3235 3238, FieldExpression.mul 3002 3185, FieldExpression.add 3235 3240, FieldExpression.mul 3005 3187, FieldExpression.add 3235 3242, FieldExpression.mul 3008 3189, FieldExpression.add 3235 3244, FieldExpression.mul 3011 3191, FieldExpression.add 3235 3246, FieldExpression.mul 3014 3193, FieldExpression.add 3235 3248, FieldExpression.mul 3017 3195, FieldExpression.add 3235 3250, FieldExpression.mul 3020 3197, FieldExpression.add 3235 3252, FieldExpression.mul 3023 3199, FieldExpression.add 3235 3254, FieldExpression.mul 3026 3201, FieldExpression.add 3235 3256, FieldExpression.mul 3029 3203, FieldExpression.add 3235 3258, FieldExpression.mul 3032 3205, FieldExpression.add 3235 3260, FieldExpression.mul 3035 3207, FieldExpression.add 3235 3262] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_102 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3264
      ([FieldExpression.mul 3038 3209, FieldExpression.add 3235 3264, FieldExpression.mul 3041 3211, FieldExpression.add 3235 3266, FieldExpression.constant 8790959064194804235, FieldExpression.add 3237 3268, FieldExpression.sub 492 3269, FieldExpression.sub 492 3268, FieldExpression.add 3268 3271, FieldExpression.mul 3272 3272, FieldExpression.mul 3273 3273, FieldExpression.mul 3273 3274, FieldExpression.mul 3272 3275, FieldExpression.add 3239 3276, FieldExpression.add 3241 3277, FieldExpression.add 3243 3278, FieldExpression.add 3245 3279, FieldExpression.add 3247 3280, FieldExpression.add 3249 3281, FieldExpression.add 3251 3282, FieldExpression.add 3253 3283, FieldExpression.add 3255 3284, FieldExpression.add 3257 3285, FieldExpression.add 3259 3286, FieldExpression.add 3261 3287, FieldExpression.add 3263 3288, FieldExpression.add 3265 3289, FieldExpression.add 3267 3290, FieldExpression.mul 2996 3276, FieldExpression.add 3291 3292, FieldExpression.mul 2999 3239, FieldExpression.add 3291 3294] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_103 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3296
      ([FieldExpression.mul 3002 3241, FieldExpression.add 3291 3296, FieldExpression.mul 3005 3243, FieldExpression.add 3291 3298, FieldExpression.mul 3008 3245, FieldExpression.add 3291 3300, FieldExpression.mul 3011 3247, FieldExpression.add 3291 3302, FieldExpression.mul 3014 3249, FieldExpression.add 3291 3304, FieldExpression.mul 3017 3251, FieldExpression.add 3291 3306, FieldExpression.mul 3020 3253, FieldExpression.add 3291 3308, FieldExpression.mul 3023 3255, FieldExpression.add 3291 3310, FieldExpression.mul 3026 3257, FieldExpression.add 3291 3312, FieldExpression.mul 3029 3259, FieldExpression.add 3291 3314, FieldExpression.mul 3032 3261, FieldExpression.add 3291 3316, FieldExpression.mul 3035 3263, FieldExpression.add 3291 3318, FieldExpression.mul 3038 3265, FieldExpression.add 3291 3320, FieldExpression.mul 3041 3267, FieldExpression.add 3291 3322, FieldExpression.constant 4582664136559626757, FieldExpression.add 3293 3324, FieldExpression.sub 493 3325, FieldExpression.sub 493 3324] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_104 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3328
      ([FieldExpression.add 3324 3327, FieldExpression.mul 3328 3328, FieldExpression.mul 3329 3329, FieldExpression.mul 3329 3330, FieldExpression.mul 3328 3331, FieldExpression.add 3295 3332, FieldExpression.add 3297 3333, FieldExpression.add 3299 3334, FieldExpression.add 3301 3335, FieldExpression.add 3303 3336, FieldExpression.add 3305 3337, FieldExpression.add 3307 3338, FieldExpression.add 3309 3339, FieldExpression.add 3311 3340, FieldExpression.add 3313 3341, FieldExpression.add 3315 3342, FieldExpression.add 3317 3343, FieldExpression.add 3319 3344, FieldExpression.add 3321 3345, FieldExpression.add 3323 3346, FieldExpression.mul 2996 3332, FieldExpression.add 3347 3348, FieldExpression.mul 2999 3295, FieldExpression.add 3347 3350, FieldExpression.mul 3002 3297, FieldExpression.add 3347 3352, FieldExpression.mul 3005 3299, FieldExpression.add 3347 3354, FieldExpression.mul 3008 3301, FieldExpression.add 3347 3356, FieldExpression.mul 3011 3303, FieldExpression.add 3347 3358] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_105 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3360
      ([FieldExpression.mul 3014 3305, FieldExpression.add 3347 3360, FieldExpression.mul 3017 3307, FieldExpression.add 3347 3362, FieldExpression.mul 3020 3309, FieldExpression.add 3347 3364, FieldExpression.mul 3023 3311, FieldExpression.add 3347 3366, FieldExpression.mul 3026 3313, FieldExpression.add 3347 3368, FieldExpression.mul 3029 3315, FieldExpression.add 3347 3370, FieldExpression.mul 3032 3317, FieldExpression.add 3347 3372, FieldExpression.mul 3035 3319, FieldExpression.add 3347 3374, FieldExpression.mul 3038 3321, FieldExpression.add 3347 3376, FieldExpression.mul 3041 3323, FieldExpression.add 3347 3378, FieldExpression.constant 14821962908959377092, FieldExpression.add 3349 3380, FieldExpression.sub 494 3381, FieldExpression.sub 494 3380, FieldExpression.add 3380 3383, FieldExpression.mul 3384 3384, FieldExpression.mul 3385 3385, FieldExpression.mul 3385 3386, FieldExpression.mul 3384 3387, FieldExpression.add 3351 3388, FieldExpression.add 3353 3389, FieldExpression.add 3355 3390] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_106 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3392
      ([FieldExpression.add 3357 3391, FieldExpression.add 3359 3392, FieldExpression.add 3361 3393, FieldExpression.add 3363 3394, FieldExpression.add 3365 3395, FieldExpression.add 3367 3396, FieldExpression.add 3369 3397, FieldExpression.add 3371 3398, FieldExpression.add 3373 3399, FieldExpression.add 3375 3400, FieldExpression.add 3377 3401, FieldExpression.add 3379 3402, FieldExpression.mul 2996 3388, FieldExpression.add 3403 3404, FieldExpression.mul 2999 3351, FieldExpression.add 3403 3406, FieldExpression.mul 3002 3353, FieldExpression.add 3403 3408, FieldExpression.mul 3005 3355, FieldExpression.add 3403 3410, FieldExpression.mul 3008 3357, FieldExpression.add 3403 3412, FieldExpression.mul 3011 3359, FieldExpression.add 3403 3414, FieldExpression.mul 3014 3361, FieldExpression.add 3403 3416, FieldExpression.mul 3017 3363, FieldExpression.add 3403 3418, FieldExpression.mul 3020 3365, FieldExpression.add 3403 3420, FieldExpression.mul 3023 3367, FieldExpression.add 3403 3422] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_107 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3424
      ([FieldExpression.mul 3026 3369, FieldExpression.add 3403 3424, FieldExpression.mul 3029 3371, FieldExpression.add 3403 3426, FieldExpression.mul 3032 3373, FieldExpression.add 3403 3428, FieldExpression.mul 3035 3375, FieldExpression.add 3403 3430, FieldExpression.mul 3038 3377, FieldExpression.add 3403 3432, FieldExpression.mul 3041 3379, FieldExpression.add 3403 3434, FieldExpression.constant 2002685046256118388, FieldExpression.add 3405 3436, FieldExpression.sub 495 3437, FieldExpression.sub 495 3436, FieldExpression.add 3436 3439, FieldExpression.mul 3440 3440, FieldExpression.mul 3441 3441, FieldExpression.mul 3441 3442, FieldExpression.mul 3440 3443, FieldExpression.add 3407 3444, FieldExpression.add 3409 3445, FieldExpression.add 3411 3446, FieldExpression.add 3413 3447, FieldExpression.add 3415 3448, FieldExpression.add 3417 3449, FieldExpression.add 3419 3450, FieldExpression.add 3421 3451, FieldExpression.add 3423 3452, FieldExpression.add 3425 3453, FieldExpression.add 3427 3454] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_108 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3456
      ([FieldExpression.add 3429 3455, FieldExpression.add 3431 3456, FieldExpression.add 3433 3457, FieldExpression.add 3435 3458, FieldExpression.mul 2996 3444, FieldExpression.add 3459 3460, FieldExpression.mul 2999 3407, FieldExpression.add 3459 3462, FieldExpression.mul 3002 3409, FieldExpression.add 3459 3464, FieldExpression.mul 3005 3411, FieldExpression.add 3459 3466, FieldExpression.mul 3008 3413, FieldExpression.add 3459 3468, FieldExpression.mul 3011 3415, FieldExpression.add 3459 3470, FieldExpression.mul 3014 3417, FieldExpression.add 3459 3472, FieldExpression.mul 3017 3419, FieldExpression.add 3459 3474, FieldExpression.mul 3020 3421, FieldExpression.add 3459 3476, FieldExpression.mul 3023 3423, FieldExpression.add 3459 3478, FieldExpression.mul 3026 3425, FieldExpression.add 3459 3480, FieldExpression.mul 3029 3427, FieldExpression.add 3459 3482, FieldExpression.mul 3032 3429, FieldExpression.add 3459 3484, FieldExpression.mul 3035 3431, FieldExpression.add 3459 3486] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_109 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3488
      ([FieldExpression.mul 3038 3433, FieldExpression.add 3459 3488, FieldExpression.mul 3041 3435, FieldExpression.add 3459 3490, FieldExpression.constant 15689593639089632368, FieldExpression.add 3461 3492, FieldExpression.sub 496 3493, FieldExpression.sub 496 3492, FieldExpression.add 3492 3495, FieldExpression.mul 3496 3496, FieldExpression.mul 3497 3497, FieldExpression.mul 3497 3498, FieldExpression.mul 3496 3499, FieldExpression.add 3463 3500, FieldExpression.add 3465 3501, FieldExpression.add 3467 3502, FieldExpression.add 3469 3503, FieldExpression.add 3471 3504, FieldExpression.add 3473 3505, FieldExpression.add 3475 3506, FieldExpression.add 3477 3507, FieldExpression.add 3479 3508, FieldExpression.add 3481 3509, FieldExpression.add 3483 3510, FieldExpression.add 3485 3511, FieldExpression.add 3487 3512, FieldExpression.add 3489 3513, FieldExpression.add 3491 3514, FieldExpression.mul 2996 3500, FieldExpression.add 3515 3516, FieldExpression.mul 2999 3463, FieldExpression.add 3515 3518] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_110 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3520
      ([FieldExpression.mul 3002 3465, FieldExpression.add 3515 3520, FieldExpression.mul 3005 3467, FieldExpression.add 3515 3522, FieldExpression.mul 3008 3469, FieldExpression.add 3515 3524, FieldExpression.mul 3011 3471, FieldExpression.add 3515 3526, FieldExpression.mul 3014 3473, FieldExpression.add 3515 3528, FieldExpression.mul 3017 3475, FieldExpression.add 3515 3530, FieldExpression.mul 3020 3477, FieldExpression.add 3515 3532, FieldExpression.mul 3023 3479, FieldExpression.add 3515 3534, FieldExpression.mul 3026 3481, FieldExpression.add 3515 3536, FieldExpression.mul 3029 3483, FieldExpression.add 3515 3538, FieldExpression.mul 3032 3485, FieldExpression.add 3515 3540, FieldExpression.mul 3035 3487, FieldExpression.add 3515 3542, FieldExpression.mul 3038 3489, FieldExpression.add 3515 3544, FieldExpression.mul 3041 3491, FieldExpression.add 3515 3546, FieldExpression.constant 10512046881800463697, FieldExpression.add 3517 3548, FieldExpression.sub 497 3549, FieldExpression.sub 497 3548] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_111 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3552
      ([FieldExpression.add 3548 3551, FieldExpression.mul 3552 3552, FieldExpression.mul 3553 3553, FieldExpression.mul 3553 3554, FieldExpression.mul 3552 3555, FieldExpression.add 3519 3556, FieldExpression.add 3521 3557, FieldExpression.add 3523 3558, FieldExpression.add 3525 3559, FieldExpression.add 3527 3560, FieldExpression.add 3529 3561, FieldExpression.add 3531 3562, FieldExpression.add 3533 3563, FieldExpression.add 3535 3564, FieldExpression.add 3537 3565, FieldExpression.add 3539 3566, FieldExpression.add 3541 3567, FieldExpression.add 3543 3568, FieldExpression.add 3545 3569, FieldExpression.add 3547 3570, FieldExpression.mul 2996 3556, FieldExpression.add 3571 3572, FieldExpression.mul 2999 3519, FieldExpression.add 3571 3574, FieldExpression.mul 3002 3521, FieldExpression.add 3571 3576, FieldExpression.mul 3005 3523, FieldExpression.add 3571 3578, FieldExpression.mul 3008 3525, FieldExpression.add 3571 3580, FieldExpression.mul 3011 3527, FieldExpression.add 3571 3582] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_112 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3584
      ([FieldExpression.mul 3014 3529, FieldExpression.add 3571 3584, FieldExpression.mul 3017 3531, FieldExpression.add 3571 3586, FieldExpression.mul 3020 3533, FieldExpression.add 3571 3588, FieldExpression.mul 3023 3535, FieldExpression.add 3571 3590, FieldExpression.mul 3026 3537, FieldExpression.add 3571 3592, FieldExpression.mul 3029 3539, FieldExpression.add 3571 3594, FieldExpression.mul 3032 3541, FieldExpression.add 3571 3596, FieldExpression.mul 3035 3543, FieldExpression.add 3571 3598, FieldExpression.mul 3038 3545, FieldExpression.add 3571 3600, FieldExpression.mul 3041 3547, FieldExpression.add 3571 3602, FieldExpression.constant 11973738501993105496, FieldExpression.add 3573 3604, FieldExpression.sub 498 3605, FieldExpression.sub 498 3604, FieldExpression.add 3604 3607, FieldExpression.mul 3608 3608, FieldExpression.mul 3609 3609, FieldExpression.mul 3609 3610, FieldExpression.mul 3608 3611, FieldExpression.add 3575 3612, FieldExpression.add 3577 3613, FieldExpression.add 3579 3614] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_113 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3616
      ([FieldExpression.add 3581 3615, FieldExpression.add 3583 3616, FieldExpression.add 3585 3617, FieldExpression.add 3587 3618, FieldExpression.add 3589 3619, FieldExpression.add 3591 3620, FieldExpression.add 3593 3621, FieldExpression.add 3595 3622, FieldExpression.add 3597 3623, FieldExpression.add 3599 3624, FieldExpression.add 3601 3625, FieldExpression.add 3603 3626, FieldExpression.mul 2996 3612, FieldExpression.add 3627 3628, FieldExpression.mul 2999 3575, FieldExpression.add 3627 3630, FieldExpression.mul 3002 3577, FieldExpression.add 3627 3632, FieldExpression.mul 3005 3579, FieldExpression.add 3627 3634, FieldExpression.mul 3008 3581, FieldExpression.add 3627 3636, FieldExpression.mul 3011 3583, FieldExpression.add 3627 3638, FieldExpression.mul 3014 3585, FieldExpression.add 3627 3640, FieldExpression.mul 3017 3587, FieldExpression.add 3627 3642, FieldExpression.mul 3020 3589, FieldExpression.add 3627 3644, FieldExpression.mul 3023 3591, FieldExpression.add 3627 3646] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_114 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3648
      ([FieldExpression.mul 3026 3593, FieldExpression.add 3627 3648, FieldExpression.mul 3029 3595, FieldExpression.add 3627 3650, FieldExpression.mul 3032 3597, FieldExpression.add 3627 3652, FieldExpression.mul 3035 3599, FieldExpression.add 3627 3654, FieldExpression.mul 3038 3601, FieldExpression.add 3627 3656, FieldExpression.mul 3041 3603, FieldExpression.add 3627 3658, FieldExpression.constant 13009070935614847359, FieldExpression.add 3629 3660, FieldExpression.sub 499 3661, FieldExpression.sub 499 3660, FieldExpression.add 3660 3663, FieldExpression.mul 3664 3664, FieldExpression.mul 3665 3665, FieldExpression.mul 3665 3666, FieldExpression.mul 3664 3667, FieldExpression.add 3631 3668, FieldExpression.add 3633 3669, FieldExpression.add 3635 3670, FieldExpression.add 3637 3671, FieldExpression.add 3639 3672, FieldExpression.add 3641 3673, FieldExpression.add 3643 3674, FieldExpression.add 3645 3675, FieldExpression.add 3647 3676, FieldExpression.add 3649 3677, FieldExpression.add 3651 3678] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_115 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3680
      ([FieldExpression.add 3653 3679, FieldExpression.add 3655 3680, FieldExpression.add 3657 3681, FieldExpression.add 3659 3682, FieldExpression.mul 2996 3668, FieldExpression.add 3683 3684, FieldExpression.mul 2999 3631, FieldExpression.add 3683 3686, FieldExpression.mul 3002 3633, FieldExpression.add 3683 3688, FieldExpression.mul 3005 3635, FieldExpression.add 3683 3690, FieldExpression.mul 3008 3637, FieldExpression.add 3683 3692, FieldExpression.mul 3011 3639, FieldExpression.add 3683 3694, FieldExpression.mul 3014 3641, FieldExpression.add 3683 3696, FieldExpression.mul 3017 3643, FieldExpression.add 3683 3698, FieldExpression.mul 3020 3645, FieldExpression.add 3683 3700, FieldExpression.mul 3023 3647, FieldExpression.add 3683 3702, FieldExpression.mul 3026 3649, FieldExpression.add 3683 3704, FieldExpression.mul 3029 3651, FieldExpression.add 3683 3706, FieldExpression.mul 3032 3653, FieldExpression.add 3683 3708, FieldExpression.mul 3035 3655, FieldExpression.add 3683 3710] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_116 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3712
      ([FieldExpression.mul 3038 3657, FieldExpression.add 3683 3712, FieldExpression.mul 3041 3659, FieldExpression.add 3683 3714, FieldExpression.constant 12908033183314664096, FieldExpression.add 3685 3716, FieldExpression.sub 500 3717, FieldExpression.sub 500 3716, FieldExpression.add 3716 3719, FieldExpression.mul 3720 3720, FieldExpression.mul 3721 3721, FieldExpression.mul 3721 3722, FieldExpression.mul 3720 3723, FieldExpression.add 3687 3724, FieldExpression.add 3689 3725, FieldExpression.add 3691 3726, FieldExpression.add 3693 3727, FieldExpression.add 3695 3728, FieldExpression.add 3697 3729, FieldExpression.add 3699 3730, FieldExpression.add 3701 3731, FieldExpression.add 3703 3732, FieldExpression.add 3705 3733, FieldExpression.add 3707 3734, FieldExpression.add 3709 3735, FieldExpression.add 3711 3736, FieldExpression.add 3713 3737, FieldExpression.add 3715 3738, FieldExpression.mul 2996 3724, FieldExpression.add 3739 3740, FieldExpression.mul 2999 3687, FieldExpression.add 3739 3742] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_117 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3744
      ([FieldExpression.mul 3002 3689, FieldExpression.add 3739 3744, FieldExpression.mul 3005 3691, FieldExpression.add 3739 3746, FieldExpression.mul 3008 3693, FieldExpression.add 3739 3748, FieldExpression.mul 3011 3695, FieldExpression.add 3739 3750, FieldExpression.mul 3014 3697, FieldExpression.add 3739 3752, FieldExpression.mul 3017 3699, FieldExpression.add 3739 3754, FieldExpression.mul 3020 3701, FieldExpression.add 3739 3756, FieldExpression.mul 3023 3703, FieldExpression.add 3739 3758, FieldExpression.mul 3026 3705, FieldExpression.add 3739 3760, FieldExpression.mul 3029 3707, FieldExpression.add 3739 3762, FieldExpression.mul 3032 3709, FieldExpression.add 3739 3764, FieldExpression.mul 3035 3711, FieldExpression.add 3739 3766, FieldExpression.mul 3038 3713, FieldExpression.add 3739 3768, FieldExpression.mul 3041 3715, FieldExpression.add 3739 3770, FieldExpression.constant 9530849385991780809, FieldExpression.add 3741 3772, FieldExpression.sub 501 3773, FieldExpression.sub 501 3772] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_118 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3776
      ([FieldExpression.add 3772 3775, FieldExpression.mul 3776 3776, FieldExpression.mul 3777 3777, FieldExpression.mul 3777 3778, FieldExpression.mul 3776 3779, FieldExpression.add 3743 3780, FieldExpression.add 3745 3781, FieldExpression.add 3747 3782, FieldExpression.add 3749 3783, FieldExpression.add 3751 3784, FieldExpression.add 3753 3785, FieldExpression.add 3755 3786, FieldExpression.add 3757 3787, FieldExpression.add 3759 3788, FieldExpression.add 3761 3789, FieldExpression.add 3763 3790, FieldExpression.add 3765 3791, FieldExpression.add 3767 3792, FieldExpression.add 3769 3793, FieldExpression.add 3771 3794, FieldExpression.mul 2996 3780, FieldExpression.add 3795 3796, FieldExpression.mul 2999 3743, FieldExpression.add 3795 3798, FieldExpression.mul 3002 3745, FieldExpression.add 3795 3800, FieldExpression.mul 3005 3747, FieldExpression.add 3795 3802, FieldExpression.mul 3008 3749, FieldExpression.add 3795 3804, FieldExpression.mul 3011 3751, FieldExpression.add 3795 3806] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_119 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3808
      ([FieldExpression.mul 3014 3753, FieldExpression.add 3795 3808, FieldExpression.mul 3017 3755, FieldExpression.add 3795 3810, FieldExpression.mul 3020 3757, FieldExpression.add 3795 3812, FieldExpression.mul 3023 3759, FieldExpression.add 3795 3814, FieldExpression.mul 3026 3761, FieldExpression.add 3795 3816, FieldExpression.mul 3029 3763, FieldExpression.add 3795 3818, FieldExpression.mul 3032 3765, FieldExpression.add 3795 3820, FieldExpression.mul 3035 3767, FieldExpression.add 3795 3822, FieldExpression.mul 3038 3769, FieldExpression.add 3795 3824, FieldExpression.mul 3041 3771, FieldExpression.add 3795 3826, FieldExpression.constant 17528314872631229800, FieldExpression.add 3797 3828, FieldExpression.sub 502 3829, FieldExpression.sub 502 3828, FieldExpression.add 3828 3831, FieldExpression.mul 3832 3832, FieldExpression.mul 3833 3833, FieldExpression.mul 3833 3834, FieldExpression.mul 3832 3835, FieldExpression.add 3799 3836, FieldExpression.add 3801 3837, FieldExpression.add 3803 3838] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_120 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3840
      ([FieldExpression.add 3805 3839, FieldExpression.add 3807 3840, FieldExpression.add 3809 3841, FieldExpression.add 3811 3842, FieldExpression.add 3813 3843, FieldExpression.add 3815 3844, FieldExpression.add 3817 3845, FieldExpression.add 3819 3846, FieldExpression.add 3821 3847, FieldExpression.add 3823 3848, FieldExpression.add 3825 3849, FieldExpression.add 3827 3850, FieldExpression.mul 2996 3836, FieldExpression.add 3851 3852, FieldExpression.mul 2999 3799, FieldExpression.add 3851 3854, FieldExpression.mul 3002 3801, FieldExpression.add 3851 3856, FieldExpression.mul 3005 3803, FieldExpression.add 3851 3858, FieldExpression.mul 3008 3805, FieldExpression.add 3851 3860, FieldExpression.mul 3011 3807, FieldExpression.add 3851 3862, FieldExpression.mul 3014 3809, FieldExpression.add 3851 3864, FieldExpression.mul 3017 3811, FieldExpression.add 3851 3866, FieldExpression.mul 3020 3813, FieldExpression.add 3851 3868, FieldExpression.mul 3023 3815, FieldExpression.add 3851 3870] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_121 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3872
      ([FieldExpression.mul 3026 3817, FieldExpression.add 3851 3872, FieldExpression.mul 3029 3819, FieldExpression.add 3851 3874, FieldExpression.mul 3032 3821, FieldExpression.add 3851 3876, FieldExpression.mul 3035 3823, FieldExpression.add 3851 3878, FieldExpression.mul 3038 3825, FieldExpression.add 3851 3880, FieldExpression.mul 3041 3827, FieldExpression.add 3851 3882, FieldExpression.constant 17869527288639567155, FieldExpression.add 3853 3884, FieldExpression.sub 503 3885, FieldExpression.sub 503 3884, FieldExpression.add 3884 3887, FieldExpression.mul 3888 3888, FieldExpression.mul 3889 3889, FieldExpression.mul 3889 3890, FieldExpression.mul 3888 3891, FieldExpression.add 3855 3892, FieldExpression.add 3857 3893, FieldExpression.add 3859 3894, FieldExpression.add 3861 3895, FieldExpression.add 3863 3896, FieldExpression.add 3865 3897, FieldExpression.add 3867 3898, FieldExpression.add 3869 3899, FieldExpression.add 3871 3900, FieldExpression.add 3873 3901, FieldExpression.add 3875 3902] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_122 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3904
      ([FieldExpression.add 3877 3903, FieldExpression.add 3879 3904, FieldExpression.add 3881 3905, FieldExpression.add 3883 3906, FieldExpression.mul 2996 3892, FieldExpression.add 3907 3908, FieldExpression.mul 2999 3855, FieldExpression.add 3907 3910, FieldExpression.mul 3002 3857, FieldExpression.add 3907 3912, FieldExpression.mul 3005 3859, FieldExpression.add 3907 3914, FieldExpression.mul 3008 3861, FieldExpression.add 3907 3916, FieldExpression.mul 3011 3863, FieldExpression.add 3907 3918, FieldExpression.mul 3014 3865, FieldExpression.add 3907 3920, FieldExpression.mul 3017 3867, FieldExpression.add 3907 3922, FieldExpression.mul 3020 3869, FieldExpression.add 3907 3924, FieldExpression.mul 3023 3871, FieldExpression.add 3907 3926, FieldExpression.mul 3026 3873, FieldExpression.add 3907 3928, FieldExpression.mul 3029 3875, FieldExpression.add 3907 3930, FieldExpression.mul 3032 3877, FieldExpression.add 3907 3932, FieldExpression.mul 3035 3879, FieldExpression.add 3907 3934] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_123 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3936
      ([FieldExpression.mul 3038 3881, FieldExpression.add 3907 3936, FieldExpression.mul 3041 3883, FieldExpression.add 3907 3938, FieldExpression.constant 7829055113315023688, FieldExpression.add 3909 3940, FieldExpression.sub 504 3941, FieldExpression.sub 504 3940, FieldExpression.add 3940 3943, FieldExpression.mul 3944 3944, FieldExpression.mul 3945 3945, FieldExpression.mul 3945 3946, FieldExpression.mul 3944 3947, FieldExpression.add 3911 3948, FieldExpression.add 3913 3949, FieldExpression.add 3915 3950, FieldExpression.add 3917 3951, FieldExpression.add 3919 3952, FieldExpression.add 3921 3953, FieldExpression.add 3923 3954, FieldExpression.add 3925 3955, FieldExpression.add 3927 3956, FieldExpression.add 3929 3957, FieldExpression.add 3931 3958, FieldExpression.add 3933 3959, FieldExpression.add 3935 3960, FieldExpression.add 3937 3961, FieldExpression.add 3939 3962, FieldExpression.mul 2996 3948, FieldExpression.add 3963 3964, FieldExpression.mul 2999 3911, FieldExpression.add 3963 3966] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_124 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 3968
      ([FieldExpression.mul 3002 3913, FieldExpression.add 3963 3968, FieldExpression.mul 3005 3915, FieldExpression.add 3963 3970, FieldExpression.mul 3008 3917, FieldExpression.add 3963 3972, FieldExpression.mul 3011 3919, FieldExpression.add 3963 3974, FieldExpression.mul 3014 3921, FieldExpression.add 3963 3976, FieldExpression.mul 3017 3923, FieldExpression.add 3963 3978, FieldExpression.mul 3020 3925, FieldExpression.add 3963 3980, FieldExpression.mul 3023 3927, FieldExpression.add 3963 3982, FieldExpression.mul 3026 3929, FieldExpression.add 3963 3984, FieldExpression.mul 3029 3931, FieldExpression.add 3963 3986, FieldExpression.mul 3032 3933, FieldExpression.add 3963 3988, FieldExpression.mul 3035 3935, FieldExpression.add 3963 3990, FieldExpression.mul 3038 3937, FieldExpression.add 3963 3992, FieldExpression.mul 3041 3939, FieldExpression.add 3963 3994, FieldExpression.constant 3256047469251174543, FieldExpression.add 3965 3996, FieldExpression.sub 505 3997, FieldExpression.sub 505 3996] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_125 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4000
      ([FieldExpression.add 3996 3999, FieldExpression.mul 4000 4000, FieldExpression.mul 4001 4001, FieldExpression.mul 4001 4002, FieldExpression.mul 4000 4003, FieldExpression.add 3967 4004, FieldExpression.add 3969 4005, FieldExpression.add 3971 4006, FieldExpression.add 3973 4007, FieldExpression.add 3975 4008, FieldExpression.add 3977 4009, FieldExpression.add 3979 4010, FieldExpression.add 3981 4011, FieldExpression.add 3983 4012, FieldExpression.add 3985 4013, FieldExpression.add 3987 4014, FieldExpression.add 3989 4015, FieldExpression.add 3991 4016, FieldExpression.add 3993 4017, FieldExpression.add 3995 4018, FieldExpression.mul 2996 4004, FieldExpression.add 4019 4020, FieldExpression.mul 2999 3967, FieldExpression.add 4019 4022, FieldExpression.mul 3002 3969, FieldExpression.add 4019 4024, FieldExpression.mul 3005 3971, FieldExpression.add 4019 4026, FieldExpression.mul 3008 3973, FieldExpression.add 4019 4028, FieldExpression.mul 3011 3975, FieldExpression.add 4019 4030] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_126 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4032
      ([FieldExpression.mul 3014 3977, FieldExpression.add 4019 4032, FieldExpression.mul 3017 3979, FieldExpression.add 4019 4034, FieldExpression.mul 3020 3981, FieldExpression.add 4019 4036, FieldExpression.mul 3023 3983, FieldExpression.add 4019 4038, FieldExpression.mul 3026 3985, FieldExpression.add 4019 4040, FieldExpression.mul 3029 3987, FieldExpression.add 4019 4042, FieldExpression.mul 3032 3989, FieldExpression.add 4019 4044, FieldExpression.mul 3035 3991, FieldExpression.add 4019 4046, FieldExpression.mul 3038 3993, FieldExpression.add 4019 4048, FieldExpression.mul 3041 3995, FieldExpression.add 4019 4050, FieldExpression.constant 3015723851705964382, FieldExpression.add 4021 4052, FieldExpression.sub 506 4053, FieldExpression.sub 506 4052, FieldExpression.add 4052 4055, FieldExpression.mul 4056 4056, FieldExpression.mul 4057 4057, FieldExpression.mul 4057 4058, FieldExpression.mul 4056 4059, FieldExpression.add 4023 4060, FieldExpression.add 4025 4061, FieldExpression.add 4027 4062] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_127 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4064
      ([FieldExpression.add 4029 4063, FieldExpression.add 4031 4064, FieldExpression.add 4033 4065, FieldExpression.add 4035 4066, FieldExpression.add 4037 4067, FieldExpression.add 4039 4068, FieldExpression.add 4041 4069, FieldExpression.add 4043 4070, FieldExpression.add 4045 4071, FieldExpression.add 4047 4072, FieldExpression.add 4049 4073, FieldExpression.add 4051 4074, FieldExpression.mul 2996 4060, FieldExpression.add 4075 4076, FieldExpression.mul 2999 4023, FieldExpression.add 4075 4078, FieldExpression.mul 3002 4025, FieldExpression.add 4075 4080, FieldExpression.mul 3005 4027, FieldExpression.add 4075 4082, FieldExpression.mul 3008 4029, FieldExpression.add 4075 4084, FieldExpression.mul 3011 4031, FieldExpression.add 4075 4086, FieldExpression.mul 3014 4033, FieldExpression.add 4075 4088, FieldExpression.mul 3017 4035, FieldExpression.add 4075 4090, FieldExpression.mul 3020 4037, FieldExpression.add 4075 4092, FieldExpression.mul 3023 4039, FieldExpression.add 4075 4094] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_128 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4096
      ([FieldExpression.mul 3026 4041, FieldExpression.add 4075 4096, FieldExpression.mul 3029 4043, FieldExpression.add 4075 4098, FieldExpression.mul 3032 4045, FieldExpression.add 4075 4100, FieldExpression.mul 3035 4047, FieldExpression.add 4075 4102, FieldExpression.mul 3038 4049, FieldExpression.add 4075 4104, FieldExpression.mul 3041 4051, FieldExpression.add 4075 4106, FieldExpression.constant 5177282273995529875, FieldExpression.add 4077 4108, FieldExpression.sub 507 4109, FieldExpression.sub 507 4108, FieldExpression.add 4108 4111, FieldExpression.mul 4112 4112, FieldExpression.mul 4113 4113, FieldExpression.mul 4113 4114, FieldExpression.mul 4112 4115, FieldExpression.add 4079 4116, FieldExpression.add 4081 4117, FieldExpression.add 4083 4118, FieldExpression.add 4085 4119, FieldExpression.add 4087 4120, FieldExpression.add 4089 4121, FieldExpression.add 4091 4122, FieldExpression.add 4093 4123, FieldExpression.add 4095 4124, FieldExpression.add 4097 4125, FieldExpression.add 4099 4126] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_129 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4128
      ([FieldExpression.add 4101 4127, FieldExpression.add 4103 4128, FieldExpression.add 4105 4129, FieldExpression.add 4107 4130, FieldExpression.mul 2996 4116, FieldExpression.add 4131 4132, FieldExpression.mul 2999 4079, FieldExpression.add 4131 4134, FieldExpression.mul 3002 4081, FieldExpression.add 4131 4136, FieldExpression.mul 3005 4083, FieldExpression.add 4131 4138, FieldExpression.mul 3008 4085, FieldExpression.add 4131 4140, FieldExpression.mul 3011 4087, FieldExpression.add 4131 4142, FieldExpression.mul 3014 4089, FieldExpression.add 4131 4144, FieldExpression.mul 3017 4091, FieldExpression.add 4131 4146, FieldExpression.mul 3020 4093, FieldExpression.add 4131 4148, FieldExpression.mul 3023 4095, FieldExpression.add 4131 4150, FieldExpression.mul 3026 4097, FieldExpression.add 4131 4152, FieldExpression.mul 3029 4099, FieldExpression.add 4131 4154, FieldExpression.mul 3032 4101, FieldExpression.add 4131 4156, FieldExpression.mul 3035 4103, FieldExpression.add 4131 4158] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_130 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4160
      ([FieldExpression.mul 3038 4105, FieldExpression.add 4131 4160, FieldExpression.mul 3041 4107, FieldExpression.add 4131 4162, FieldExpression.constant 16035152896984012190, FieldExpression.add 4133 4164, FieldExpression.sub 508 4165, FieldExpression.sub 508 4164, FieldExpression.add 4164 4167, FieldExpression.mul 4168 4168, FieldExpression.mul 4169 4169, FieldExpression.mul 4169 4170, FieldExpression.mul 4168 4171, FieldExpression.add 4135 4172, FieldExpression.add 4137 4173, FieldExpression.add 4139 4174, FieldExpression.add 4141 4175, FieldExpression.add 4143 4176, FieldExpression.add 4145 4177, FieldExpression.add 4147 4178, FieldExpression.add 4149 4179, FieldExpression.add 4151 4180, FieldExpression.add 4153 4181, FieldExpression.add 4155 4182, FieldExpression.add 4157 4183, FieldExpression.add 4159 4184, FieldExpression.add 4161 4185, FieldExpression.add 4163 4186, FieldExpression.mul 2996 4172, FieldExpression.add 4187 4188, FieldExpression.mul 2999 4135, FieldExpression.add 4187 4190] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_131 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4192
      ([FieldExpression.mul 3002 4137, FieldExpression.add 4187 4192, FieldExpression.mul 3005 4139, FieldExpression.add 4187 4194, FieldExpression.mul 3008 4141, FieldExpression.add 4187 4196, FieldExpression.mul 3011 4143, FieldExpression.add 4187 4198, FieldExpression.mul 3014 4145, FieldExpression.add 4187 4200, FieldExpression.mul 3017 4147, FieldExpression.add 4187 4202, FieldExpression.mul 3020 4149, FieldExpression.add 4187 4204, FieldExpression.mul 3023 4151, FieldExpression.add 4187 4206, FieldExpression.mul 3026 4153, FieldExpression.add 4187 4208, FieldExpression.mul 3029 4155, FieldExpression.add 4187 4210, FieldExpression.mul 3032 4157, FieldExpression.add 4187 4212, FieldExpression.mul 3035 4159, FieldExpression.add 4187 4214, FieldExpression.mul 3038 4161, FieldExpression.add 4187 4216, FieldExpression.mul 3041 4163, FieldExpression.add 4187 4218, FieldExpression.constant 15766898731627159621, FieldExpression.add 4189 4220, FieldExpression.sub 509 4221, FieldExpression.sub 509 4220] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_132 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4224
      ([FieldExpression.constant 6714370142978148338, FieldExpression.add 4191 4224, FieldExpression.sub 510 4225, FieldExpression.sub 510 4224, FieldExpression.constant 5906664861467821209, FieldExpression.add 4193 4228, FieldExpression.sub 511 4229, FieldExpression.sub 511 4228, FieldExpression.constant 2197120128337974909, FieldExpression.add 4195 4232, FieldExpression.sub 512 4233, FieldExpression.sub 512 4232, FieldExpression.constant 9400421283898153864, FieldExpression.add 4197 4236, FieldExpression.sub 513 4237, FieldExpression.sub 513 4236, FieldExpression.constant 16740473708727660723, FieldExpression.add 4199 4240, FieldExpression.sub 514 4241, FieldExpression.sub 514 4240, FieldExpression.constant 7287335615015370599, FieldExpression.add 4201 4244, FieldExpression.sub 515 4245, FieldExpression.sub 515 4244, FieldExpression.constant 12399217337488717232, FieldExpression.add 4203 4248, FieldExpression.sub 516 4249, FieldExpression.sub 516 4248, FieldExpression.constant 12655834778591227242, FieldExpression.add 4205 4252, FieldExpression.sub 517 4253, FieldExpression.sub 517 4252] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_133 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4256
      ([FieldExpression.constant 7516917516498792203, FieldExpression.add 4207 4256, FieldExpression.sub 518 4257, FieldExpression.sub 518 4256, FieldExpression.constant 17291898461659961460, FieldExpression.add 4209 4260, FieldExpression.sub 519 4261, FieldExpression.sub 519 4260, FieldExpression.constant 3483661079725019706, FieldExpression.add 4211 4264, FieldExpression.sub 520 4265, FieldExpression.sub 520 4264, FieldExpression.constant 18038566855851505564, FieldExpression.add 4213 4268, FieldExpression.sub 521 4269, FieldExpression.sub 521 4268, FieldExpression.constant 6166154478921479976, FieldExpression.add 4215 4272, FieldExpression.sub 522 4273, FieldExpression.sub 522 4272, FieldExpression.constant 8824538844032254328, FieldExpression.add 4217 4276, FieldExpression.sub 523 4277, FieldExpression.sub 523 4276, FieldExpression.constant 17138720803294251067, FieldExpression.add 4219 4280, FieldExpression.sub 524 4281, FieldExpression.sub 524 4280, FieldExpression.add 4220 4223, FieldExpression.mul 4284 4284, FieldExpression.mul 4285 4285, FieldExpression.mul 4285 4286] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_134 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4288
      ([FieldExpression.mul 4284 4287, FieldExpression.add 4224 4227, FieldExpression.mul 4289 4289, FieldExpression.mul 4290 4290, FieldExpression.mul 4290 4291, FieldExpression.mul 4289 4292, FieldExpression.add 4228 4231, FieldExpression.mul 4294 4294, FieldExpression.mul 4295 4295, FieldExpression.mul 4295 4296, FieldExpression.mul 4294 4297, FieldExpression.add 4232 4235, FieldExpression.mul 4299 4299, FieldExpression.mul 4300 4300, FieldExpression.mul 4300 4301, FieldExpression.mul 4299 4302, FieldExpression.add 4236 4239, FieldExpression.mul 4304 4304, FieldExpression.mul 4305 4305, FieldExpression.mul 4305 4306, FieldExpression.mul 4304 4307, FieldExpression.add 4240 4243, FieldExpression.mul 4309 4309, FieldExpression.mul 4310 4310, FieldExpression.mul 4310 4311, FieldExpression.mul 4309 4312, FieldExpression.add 4244 4247, FieldExpression.mul 4314 4314, FieldExpression.mul 4315 4315, FieldExpression.mul 4315 4316, FieldExpression.mul 4314 4317, FieldExpression.add 4248 4251] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_135 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4320
      ([FieldExpression.mul 4319 4319, FieldExpression.mul 4320 4320, FieldExpression.mul 4320 4321, FieldExpression.mul 4319 4322, FieldExpression.add 4252 4255, FieldExpression.mul 4324 4324, FieldExpression.mul 4325 4325, FieldExpression.mul 4325 4326, FieldExpression.mul 4324 4327, FieldExpression.add 4256 4259, FieldExpression.mul 4329 4329, FieldExpression.mul 4330 4330, FieldExpression.mul 4330 4331, FieldExpression.mul 4329 4332, FieldExpression.add 4260 4263, FieldExpression.mul 4334 4334, FieldExpression.mul 4335 4335, FieldExpression.mul 4335 4336, FieldExpression.mul 4334 4337, FieldExpression.add 4264 4267, FieldExpression.mul 4339 4339, FieldExpression.mul 4340 4340, FieldExpression.mul 4340 4341, FieldExpression.mul 4339 4342, FieldExpression.add 4268 4271, FieldExpression.mul 4344 4344, FieldExpression.mul 4345 4345, FieldExpression.mul 4345 4346, FieldExpression.mul 4344 4347, FieldExpression.add 4272 4275, FieldExpression.mul 4349 4349, FieldExpression.mul 4350 4350] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_136 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4352
      ([FieldExpression.mul 4350 4351, FieldExpression.mul 4349 4352, FieldExpression.add 4276 4279, FieldExpression.mul 4354 4354, FieldExpression.mul 4355 4355, FieldExpression.mul 4355 4356, FieldExpression.mul 4354 4357, FieldExpression.add 4280 4283, FieldExpression.mul 4359 4359, FieldExpression.mul 4360 4360, FieldExpression.mul 4360 4361, FieldExpression.mul 4359 4362, FieldExpression.add 4288 4293, FieldExpression.add 4298 4364, FieldExpression.add 4303 4365, FieldExpression.add 4288 4366, FieldExpression.add 4293 4366, FieldExpression.add 4298 4366, FieldExpression.add 4303 4366, FieldExpression.add 4308 4313, FieldExpression.add 4318 4371, FieldExpression.add 4323 4372, FieldExpression.add 4308 4373, FieldExpression.add 4313 4373, FieldExpression.add 4318 4373, FieldExpression.add 4323 4373, FieldExpression.add 4328 4333, FieldExpression.add 4338 4378, FieldExpression.add 4343 4379, FieldExpression.add 4328 4380, FieldExpression.add 4333 4380, FieldExpression.add 4338 4380] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_137 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4384
      ([FieldExpression.add 4343 4380, FieldExpression.add 4348 4353, FieldExpression.add 4358 4385, FieldExpression.add 4363 4386, FieldExpression.add 4348 4387, FieldExpression.add 4353 4387, FieldExpression.add 4358 4387, FieldExpression.add 4363 4387, FieldExpression.add 4367 4374, FieldExpression.add 4381 4388, FieldExpression.add 4392 4393, FieldExpression.add 4374 4394, FieldExpression.add 4388 4394, FieldExpression.add 4367 4367, FieldExpression.add 4396 4397, FieldExpression.add 4381 4381, FieldExpression.add 4395 4399, FieldExpression.add 4392 4395, FieldExpression.add 4393 4396, FieldExpression.add 4368 4375, FieldExpression.add 4382 4389, FieldExpression.add 4403 4404, FieldExpression.add 4375 4405, FieldExpression.add 4389 4405, FieldExpression.add 4368 4368, FieldExpression.add 4407 4408, FieldExpression.add 4382 4382, FieldExpression.add 4406 4410, FieldExpression.add 4403 4406, FieldExpression.add 4404 4407, FieldExpression.add 4369 4376, FieldExpression.add 4383 4390] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_138 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4416
      ([FieldExpression.add 4414 4415, FieldExpression.add 4376 4416, FieldExpression.add 4390 4416, FieldExpression.add 4369 4369, FieldExpression.add 4418 4419, FieldExpression.add 4383 4383, FieldExpression.add 4417 4421, FieldExpression.add 4414 4417, FieldExpression.add 4415 4418, FieldExpression.add 4370 4377, FieldExpression.add 4384 4391, FieldExpression.add 4425 4426, FieldExpression.add 4377 4427, FieldExpression.add 4391 4427, FieldExpression.add 4370 4370, FieldExpression.add 4429 4430, FieldExpression.add 4384 4384, FieldExpression.add 4428 4432, FieldExpression.add 4425 4428, FieldExpression.add 4426 4429, FieldExpression.constant 4158286797471309733, FieldExpression.add 4401 4436, FieldExpression.sub 525 4437, FieldExpression.sub 525 4436, FieldExpression.constant 1589482450994236426, FieldExpression.add 4412 4440, FieldExpression.sub 526 4441, FieldExpression.sub 526 4440, FieldExpression.constant 4836112672767737407, FieldExpression.add 4423 4444, FieldExpression.sub 527 4445, FieldExpression.sub 527 4444] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_139 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4448
      ([FieldExpression.constant 6108317238076822824, FieldExpression.add 4434 4448, FieldExpression.sub 528 4449, FieldExpression.sub 528 4448, FieldExpression.constant 11174425919404088598, FieldExpression.add 4400 4452, FieldExpression.sub 529 4453, FieldExpression.sub 529 4452, FieldExpression.constant 2755155124184744585, FieldExpression.add 4411 4456, FieldExpression.sub 530 4457, FieldExpression.sub 530 4456, FieldExpression.constant 13202523778257173956, FieldExpression.add 4422 4460, FieldExpression.sub 531 4461, FieldExpression.sub 531 4460, FieldExpression.constant 6643835433125335951, FieldExpression.add 4433 4464, FieldExpression.sub 532 4465, FieldExpression.sub 532 4464, FieldExpression.constant 2748965361441888477, FieldExpression.add 4402 4468, FieldExpression.sub 533 4469, FieldExpression.sub 533 4468, FieldExpression.constant 14297205492001640506, FieldExpression.add 4413 4472, FieldExpression.sub 534 4473, FieldExpression.sub 534 4472, FieldExpression.constant 12595977886586773319, FieldExpression.add 4424 4476, FieldExpression.sub 535 4477, FieldExpression.sub 535 4476] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_140 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4480
      ([FieldExpression.constant 257624298448087449, FieldExpression.add 4435 4480, FieldExpression.sub 536 4481, FieldExpression.sub 536 4480, FieldExpression.constant 2744326799038764281, FieldExpression.add 4398 4484, FieldExpression.sub 537 4485, FieldExpression.sub 537 4484, FieldExpression.constant 9097808034015176417, FieldExpression.add 4409 4488, FieldExpression.sub 538 4489, FieldExpression.sub 538 4488, FieldExpression.constant 5523099006222423939, FieldExpression.add 4420 4492, FieldExpression.sub 539 4493, FieldExpression.sub 539 4492, FieldExpression.constant 7256201493271212720, FieldExpression.add 4431 4496, FieldExpression.sub 540 4497, FieldExpression.sub 540 4496, FieldExpression.add 4436 4439, FieldExpression.mul 4500 4500, FieldExpression.mul 4501 4501, FieldExpression.mul 4501 4502, FieldExpression.mul 4500 4503, FieldExpression.add 4440 4443, FieldExpression.mul 4505 4505, FieldExpression.mul 4506 4506, FieldExpression.mul 4506 4507, FieldExpression.mul 4505 4508, FieldExpression.add 4444 4447, FieldExpression.mul 4510 4510] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_141 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4512
      ([FieldExpression.mul 4511 4511, FieldExpression.mul 4511 4512, FieldExpression.mul 4510 4513, FieldExpression.add 4448 4451, FieldExpression.mul 4515 4515, FieldExpression.mul 4516 4516, FieldExpression.mul 4516 4517, FieldExpression.mul 4515 4518, FieldExpression.add 4452 4455, FieldExpression.mul 4520 4520, FieldExpression.mul 4521 4521, FieldExpression.mul 4521 4522, FieldExpression.mul 4520 4523, FieldExpression.add 4456 4459, FieldExpression.mul 4525 4525, FieldExpression.mul 4526 4526, FieldExpression.mul 4526 4527, FieldExpression.mul 4525 4528, FieldExpression.add 4460 4463, FieldExpression.mul 4530 4530, FieldExpression.mul 4531 4531, FieldExpression.mul 4531 4532, FieldExpression.mul 4530 4533, FieldExpression.add 4464 4467, FieldExpression.mul 4535 4535, FieldExpression.mul 4536 4536, FieldExpression.mul 4536 4537, FieldExpression.mul 4535 4538, FieldExpression.add 4468 4471, FieldExpression.mul 4540 4540, FieldExpression.mul 4541 4541, FieldExpression.mul 4541 4542] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_142 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4544
      ([FieldExpression.mul 4540 4543, FieldExpression.add 4472 4475, FieldExpression.mul 4545 4545, FieldExpression.mul 4546 4546, FieldExpression.mul 4546 4547, FieldExpression.mul 4545 4548, FieldExpression.add 4476 4479, FieldExpression.mul 4550 4550, FieldExpression.mul 4551 4551, FieldExpression.mul 4551 4552, FieldExpression.mul 4550 4553, FieldExpression.add 4480 4483, FieldExpression.mul 4555 4555, FieldExpression.mul 4556 4556, FieldExpression.mul 4556 4557, FieldExpression.mul 4555 4558, FieldExpression.add 4484 4487, FieldExpression.mul 4560 4560, FieldExpression.mul 4561 4561, FieldExpression.mul 4561 4562, FieldExpression.mul 4560 4563, FieldExpression.add 4488 4491, FieldExpression.mul 4565 4565, FieldExpression.mul 4566 4566, FieldExpression.mul 4566 4567, FieldExpression.mul 4565 4568, FieldExpression.add 4492 4495, FieldExpression.mul 4570 4570, FieldExpression.mul 4571 4571, FieldExpression.mul 4571 4572, FieldExpression.mul 4570 4573, FieldExpression.add 4496 4499] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_143 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4576
      ([FieldExpression.mul 4575 4575, FieldExpression.mul 4576 4576, FieldExpression.mul 4576 4577, FieldExpression.mul 4575 4578, FieldExpression.add 4504 4509, FieldExpression.add 4514 4580, FieldExpression.add 4519 4581, FieldExpression.add 4504 4582, FieldExpression.add 4509 4582, FieldExpression.add 4514 4582, FieldExpression.add 4519 4582, FieldExpression.add 4524 4529, FieldExpression.add 4534 4587, FieldExpression.add 4539 4588, FieldExpression.add 4524 4589, FieldExpression.add 4529 4589, FieldExpression.add 4534 4589, FieldExpression.add 4539 4589, FieldExpression.add 4544 4549, FieldExpression.add 4554 4594, FieldExpression.add 4559 4595, FieldExpression.add 4544 4596, FieldExpression.add 4549 4596, FieldExpression.add 4554 4596, FieldExpression.add 4559 4596, FieldExpression.add 4564 4569, FieldExpression.add 4574 4601, FieldExpression.add 4579 4602, FieldExpression.add 4564 4603, FieldExpression.add 4569 4603, FieldExpression.add 4574 4603, FieldExpression.add 4579 4603] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_144 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4608
      ([FieldExpression.add 4583 4590, FieldExpression.add 4597 4604, FieldExpression.add 4608 4609, FieldExpression.add 4590 4610, FieldExpression.add 4604 4610, FieldExpression.add 4583 4583, FieldExpression.add 4612 4613, FieldExpression.add 4597 4597, FieldExpression.add 4611 4615, FieldExpression.add 4608 4611, FieldExpression.add 4609 4612, FieldExpression.add 4584 4591, FieldExpression.add 4598 4605, FieldExpression.add 4619 4620, FieldExpression.add 4591 4621, FieldExpression.add 4605 4621, FieldExpression.add 4584 4584, FieldExpression.add 4623 4624, FieldExpression.add 4598 4598, FieldExpression.add 4622 4626, FieldExpression.add 4619 4622, FieldExpression.add 4620 4623, FieldExpression.add 4585 4592, FieldExpression.add 4599 4606, FieldExpression.add 4630 4631, FieldExpression.add 4592 4632, FieldExpression.add 4606 4632, FieldExpression.add 4585 4585, FieldExpression.add 4634 4635, FieldExpression.add 4599 4599, FieldExpression.add 4633 4637, FieldExpression.add 4630 4633] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_145 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4640
      ([FieldExpression.add 4631 4634, FieldExpression.add 4586 4593, FieldExpression.add 4600 4607, FieldExpression.add 4641 4642, FieldExpression.add 4593 4643, FieldExpression.add 4607 4643, FieldExpression.add 4586 4586, FieldExpression.add 4645 4646, FieldExpression.add 4600 4600, FieldExpression.add 4644 4648, FieldExpression.add 4641 4644, FieldExpression.add 4642 4645, FieldExpression.constant 9738621014989498753, FieldExpression.add 4617 4652, FieldExpression.sub 541 4653, FieldExpression.sub 541 4652, FieldExpression.constant 237412858668409460, FieldExpression.add 4628 4656, FieldExpression.sub 542 4657, FieldExpression.sub 542 4656, FieldExpression.constant 6405904454922718574, FieldExpression.add 4639 4660, FieldExpression.sub 543 4661, FieldExpression.sub 543 4660, FieldExpression.constant 16343835012250148340, FieldExpression.add 4650 4664, FieldExpression.sub 544 4665, FieldExpression.sub 544 4664, FieldExpression.constant 9342245617122491936, FieldExpression.add 4616 4668, FieldExpression.sub 545 4669, FieldExpression.sub 545 4668] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_146 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4672
      ([FieldExpression.constant 824922755340087111, FieldExpression.add 4627 4672, FieldExpression.sub 546 4673, FieldExpression.sub 546 4672, FieldExpression.constant 5398764608665671277, FieldExpression.add 4638 4676, FieldExpression.sub 547 4677, FieldExpression.sub 547 4676, FieldExpression.constant 16030622638137836774, FieldExpression.add 4649 4680, FieldExpression.sub 548 4681, FieldExpression.sub 548 4680, FieldExpression.constant 4921899302518525668, FieldExpression.add 4618 4684, FieldExpression.sub 549 4685, FieldExpression.sub 549 4684, FieldExpression.constant 10676667276121395674, FieldExpression.add 4629 4688, FieldExpression.sub 550 4689, FieldExpression.sub 550 4688, FieldExpression.constant 16304445044992359788, FieldExpression.add 4640 4692, FieldExpression.sub 551 4693, FieldExpression.sub 551 4692, FieldExpression.constant 587812931475326787, FieldExpression.add 4651 4696, FieldExpression.sub 552 4697, FieldExpression.sub 552 4696, FieldExpression.constant 7627897473303434798, FieldExpression.add 4614 4700, FieldExpression.sub 553 4701, FieldExpression.sub 553 4700] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_147 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4704
      ([FieldExpression.constant 2633542348821978290, FieldExpression.add 4625 4704, FieldExpression.sub 554 4705, FieldExpression.sub 554 4704, FieldExpression.constant 5714662808802647771, FieldExpression.add 4636 4708, FieldExpression.sub 555 4709, FieldExpression.sub 555 4708, FieldExpression.constant 15665352327749112015, FieldExpression.add 4647 4712, FieldExpression.sub 556 4713, FieldExpression.sub 556 4712, FieldExpression.add 4652 4655, FieldExpression.mul 4716 4716, FieldExpression.mul 4717 4717, FieldExpression.mul 4717 4718, FieldExpression.mul 4716 4719, FieldExpression.add 4656 4659, FieldExpression.mul 4721 4721, FieldExpression.mul 4722 4722, FieldExpression.mul 4722 4723, FieldExpression.mul 4721 4724, FieldExpression.add 4660 4663, FieldExpression.mul 4726 4726, FieldExpression.mul 4727 4727, FieldExpression.mul 4727 4728, FieldExpression.mul 4726 4729, FieldExpression.add 4664 4667, FieldExpression.mul 4731 4731, FieldExpression.mul 4732 4732, FieldExpression.mul 4732 4733, FieldExpression.mul 4731 4734] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_148 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4736
      ([FieldExpression.add 4668 4671, FieldExpression.mul 4736 4736, FieldExpression.mul 4737 4737, FieldExpression.mul 4737 4738, FieldExpression.mul 4736 4739, FieldExpression.add 4672 4675, FieldExpression.mul 4741 4741, FieldExpression.mul 4742 4742, FieldExpression.mul 4742 4743, FieldExpression.mul 4741 4744, FieldExpression.add 4676 4679, FieldExpression.mul 4746 4746, FieldExpression.mul 4747 4747, FieldExpression.mul 4747 4748, FieldExpression.mul 4746 4749, FieldExpression.add 4680 4683, FieldExpression.mul 4751 4751, FieldExpression.mul 4752 4752, FieldExpression.mul 4752 4753, FieldExpression.mul 4751 4754, FieldExpression.add 4684 4687, FieldExpression.mul 4756 4756, FieldExpression.mul 4757 4757, FieldExpression.mul 4757 4758, FieldExpression.mul 4756 4759, FieldExpression.add 4688 4691, FieldExpression.mul 4761 4761, FieldExpression.mul 4762 4762, FieldExpression.mul 4762 4763, FieldExpression.mul 4761 4764, FieldExpression.add 4692 4695, FieldExpression.mul 4766 4766] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_149 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4768
      ([FieldExpression.mul 4767 4767, FieldExpression.mul 4767 4768, FieldExpression.mul 4766 4769, FieldExpression.add 4696 4699, FieldExpression.mul 4771 4771, FieldExpression.mul 4772 4772, FieldExpression.mul 4772 4773, FieldExpression.mul 4771 4774, FieldExpression.add 4700 4703, FieldExpression.mul 4776 4776, FieldExpression.mul 4777 4777, FieldExpression.mul 4777 4778, FieldExpression.mul 4776 4779, FieldExpression.add 4704 4707, FieldExpression.mul 4781 4781, FieldExpression.mul 4782 4782, FieldExpression.mul 4782 4783, FieldExpression.mul 4781 4784, FieldExpression.add 4708 4711, FieldExpression.mul 4786 4786, FieldExpression.mul 4787 4787, FieldExpression.mul 4787 4788, FieldExpression.mul 4786 4789, FieldExpression.add 4712 4715, FieldExpression.mul 4791 4791, FieldExpression.mul 4792 4792, FieldExpression.mul 4792 4793, FieldExpression.mul 4791 4794, FieldExpression.add 4720 4725, FieldExpression.add 4730 4796, FieldExpression.add 4735 4797, FieldExpression.add 4720 4798] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_150 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4800
      ([FieldExpression.add 4725 4798, FieldExpression.add 4730 4798, FieldExpression.add 4735 4798, FieldExpression.add 4740 4745, FieldExpression.add 4750 4803, FieldExpression.add 4755 4804, FieldExpression.add 4740 4805, FieldExpression.add 4745 4805, FieldExpression.add 4750 4805, FieldExpression.add 4755 4805, FieldExpression.add 4760 4765, FieldExpression.add 4770 4810, FieldExpression.add 4775 4811, FieldExpression.add 4760 4812, FieldExpression.add 4765 4812, FieldExpression.add 4770 4812, FieldExpression.add 4775 4812, FieldExpression.add 4780 4785, FieldExpression.add 4790 4817, FieldExpression.add 4795 4818, FieldExpression.add 4780 4819, FieldExpression.add 4785 4819, FieldExpression.add 4790 4819, FieldExpression.add 4795 4819, FieldExpression.add 4799 4806, FieldExpression.add 4813 4820, FieldExpression.add 4824 4825, FieldExpression.add 4806 4826, FieldExpression.add 4820 4826, FieldExpression.add 4799 4799, FieldExpression.add 4828 4829, FieldExpression.add 4813 4813] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_151 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4832
      ([FieldExpression.add 4827 4831, FieldExpression.add 4824 4827, FieldExpression.add 4825 4828, FieldExpression.add 4800 4807, FieldExpression.add 4814 4821, FieldExpression.add 4835 4836, FieldExpression.add 4807 4837, FieldExpression.add 4821 4837, FieldExpression.add 4800 4800, FieldExpression.add 4839 4840, FieldExpression.add 4814 4814, FieldExpression.add 4838 4842, FieldExpression.add 4835 4838, FieldExpression.add 4836 4839, FieldExpression.add 4801 4808, FieldExpression.add 4815 4822, FieldExpression.add 4846 4847, FieldExpression.add 4808 4848, FieldExpression.add 4822 4848, FieldExpression.add 4801 4801, FieldExpression.add 4850 4851, FieldExpression.add 4815 4815, FieldExpression.add 4849 4853, FieldExpression.add 4846 4849, FieldExpression.add 4847 4850, FieldExpression.add 4802 4809, FieldExpression.add 4816 4823, FieldExpression.add 4857 4858, FieldExpression.add 4809 4859, FieldExpression.add 4823 4859, FieldExpression.add 4802 4802, FieldExpression.add 4861 4862] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_152 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4864
      ([FieldExpression.add 4816 4816, FieldExpression.add 4860 4864, FieldExpression.add 4857 4860, FieldExpression.add 4858 4861, FieldExpression.constant 8041781683128153420, FieldExpression.add 4833 4868, FieldExpression.sub 557 4869, FieldExpression.sub 557 4868, FieldExpression.constant 13172746155287932121, FieldExpression.add 4844 4872, FieldExpression.sub 558 4873, FieldExpression.sub 558 4872, FieldExpression.constant 6611413049825339003, FieldExpression.add 4855 4876, FieldExpression.sub 559 4877, FieldExpression.sub 559 4876, FieldExpression.constant 9076340683484238287, FieldExpression.add 4866 4880, FieldExpression.sub 560 4881, FieldExpression.sub 560 4880, FieldExpression.constant 12295614633782496176, FieldExpression.add 4832 4884, FieldExpression.sub 561 4885, FieldExpression.sub 561 4884, FieldExpression.constant 11414162089917699064, FieldExpression.add 4843 4888, FieldExpression.sub 562 4889, FieldExpression.sub 562 4888, FieldExpression.constant 13658053783093222498, FieldExpression.add 4854 4892, FieldExpression.sub 563 4893, FieldExpression.sub 563 4892] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_153 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4896
      ([FieldExpression.constant 16216654076620539925, FieldExpression.add 4865 4896, FieldExpression.sub 564 4897, FieldExpression.sub 564 4896, FieldExpression.constant 17782598995085730495, FieldExpression.add 4834 4900, FieldExpression.sub 565 4901, FieldExpression.sub 565 4900, FieldExpression.constant 18362903988365127450, FieldExpression.add 4845 4904, FieldExpression.sub 566 4905, FieldExpression.sub 566 4904, FieldExpression.constant 11596821426909532371, FieldExpression.add 4856 4908, FieldExpression.sub 567 4909, FieldExpression.sub 567 4908, FieldExpression.constant 13499421621575350806, FieldExpression.add 4867 4912, FieldExpression.sub 568 4913, FieldExpression.sub 568 4912, FieldExpression.constant 15256312875610823807, FieldExpression.add 4830 4916, FieldExpression.sub 569 4917, FieldExpression.sub 569 4916, FieldExpression.constant 1558929959921731273, FieldExpression.add 4841 4920, FieldExpression.sub 570 4921, FieldExpression.sub 570 4920, FieldExpression.constant 17567284148478398281, FieldExpression.add 4852 4924, FieldExpression.sub 571 4925, FieldExpression.sub 571 4924] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_154 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4928
      ([FieldExpression.constant 4615393526180652407, FieldExpression.add 4863 4928, FieldExpression.sub 572 4929, FieldExpression.sub 572 4928, FieldExpression.add 4868 4871, FieldExpression.mul 4932 4932, FieldExpression.mul 4933 4933, FieldExpression.mul 4933 4934, FieldExpression.mul 4932 4935, FieldExpression.add 4872 4875, FieldExpression.mul 4937 4937, FieldExpression.mul 4938 4938, FieldExpression.mul 4938 4939, FieldExpression.mul 4937 4940, FieldExpression.add 4876 4879, FieldExpression.mul 4942 4942, FieldExpression.mul 4943 4943, FieldExpression.mul 4943 4944, FieldExpression.mul 4942 4945, FieldExpression.add 4880 4883, FieldExpression.mul 4947 4947, FieldExpression.mul 4948 4948, FieldExpression.mul 4948 4949, FieldExpression.mul 4947 4950, FieldExpression.add 4884 4887, FieldExpression.mul 4952 4952, FieldExpression.mul 4953 4953, FieldExpression.mul 4953 4954, FieldExpression.mul 4952 4955, FieldExpression.add 4888 4891, FieldExpression.mul 4957 4957, FieldExpression.mul 4958 4958] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_155 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4960
      ([FieldExpression.mul 4958 4959, FieldExpression.mul 4957 4960, FieldExpression.add 4892 4895, FieldExpression.mul 4962 4962, FieldExpression.mul 4963 4963, FieldExpression.mul 4963 4964, FieldExpression.mul 4962 4965, FieldExpression.add 4896 4899, FieldExpression.mul 4967 4967, FieldExpression.mul 4968 4968, FieldExpression.mul 4968 4969, FieldExpression.mul 4967 4970, FieldExpression.add 4900 4903, FieldExpression.mul 4972 4972, FieldExpression.mul 4973 4973, FieldExpression.mul 4973 4974, FieldExpression.mul 4972 4975, FieldExpression.add 4904 4907, FieldExpression.mul 4977 4977, FieldExpression.mul 4978 4978, FieldExpression.mul 4978 4979, FieldExpression.mul 4977 4980, FieldExpression.add 4908 4911, FieldExpression.mul 4982 4982, FieldExpression.mul 4983 4983, FieldExpression.mul 4983 4984, FieldExpression.mul 4982 4985, FieldExpression.add 4912 4915, FieldExpression.mul 4987 4987, FieldExpression.mul 4988 4988, FieldExpression.mul 4988 4989, FieldExpression.mul 4987 4990] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_156 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 4992
      ([FieldExpression.add 4916 4919, FieldExpression.mul 4992 4992, FieldExpression.mul 4993 4993, FieldExpression.mul 4993 4994, FieldExpression.mul 4992 4995, FieldExpression.add 4920 4923, FieldExpression.mul 4997 4997, FieldExpression.mul 4998 4998, FieldExpression.mul 4998 4999, FieldExpression.mul 4997 5000, FieldExpression.add 4924 4927, FieldExpression.mul 5002 5002, FieldExpression.mul 5003 5003, FieldExpression.mul 5003 5004, FieldExpression.mul 5002 5005, FieldExpression.add 4928 4931, FieldExpression.mul 5007 5007, FieldExpression.mul 5008 5008, FieldExpression.mul 5008 5009, FieldExpression.mul 5007 5010, FieldExpression.add 4936 4941, FieldExpression.add 4946 5012, FieldExpression.add 4951 5013, FieldExpression.add 4936 5014, FieldExpression.add 4941 5014, FieldExpression.add 4946 5014, FieldExpression.add 4951 5014, FieldExpression.add 4956 4961, FieldExpression.add 4966 5019, FieldExpression.add 4971 5020, FieldExpression.add 4956 5021, FieldExpression.add 4961 5021] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_157 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5024
      ([FieldExpression.add 4966 5021, FieldExpression.add 4971 5021, FieldExpression.add 4976 4981, FieldExpression.add 4986 5026, FieldExpression.add 4991 5027, FieldExpression.add 4976 5028, FieldExpression.add 4981 5028, FieldExpression.add 4986 5028, FieldExpression.add 4991 5028, FieldExpression.add 4996 5001, FieldExpression.add 5006 5033, FieldExpression.add 5011 5034, FieldExpression.add 4996 5035, FieldExpression.add 5001 5035, FieldExpression.add 5006 5035, FieldExpression.add 5011 5035, FieldExpression.add 5015 5022, FieldExpression.add 5029 5036, FieldExpression.add 5040 5041, FieldExpression.add 5022 5042, FieldExpression.add 5036 5042, FieldExpression.add 5015 5015, FieldExpression.add 5044 5045, FieldExpression.add 5029 5029, FieldExpression.add 5043 5047, FieldExpression.add 5040 5043, FieldExpression.add 5041 5044, FieldExpression.add 5016 5023, FieldExpression.add 5030 5037, FieldExpression.add 5051 5052, FieldExpression.add 5023 5053, FieldExpression.add 5037 5053] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_158 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5056
      ([FieldExpression.add 5016 5016, FieldExpression.add 5055 5056, FieldExpression.add 5030 5030, FieldExpression.add 5054 5058, FieldExpression.add 5051 5054, FieldExpression.add 5052 5055, FieldExpression.add 5017 5024, FieldExpression.add 5031 5038, FieldExpression.add 5062 5063, FieldExpression.add 5024 5064, FieldExpression.add 5038 5064, FieldExpression.add 5017 5017, FieldExpression.add 5066 5067, FieldExpression.add 5031 5031, FieldExpression.add 5065 5069, FieldExpression.add 5062 5065, FieldExpression.add 5063 5066, FieldExpression.add 5018 5025, FieldExpression.add 5032 5039, FieldExpression.add 5073 5074, FieldExpression.add 5025 5075, FieldExpression.add 5039 5075, FieldExpression.add 5018 5018, FieldExpression.add 5077 5078, FieldExpression.add 5032 5032, FieldExpression.add 5076 5080, FieldExpression.add 5073 5076, FieldExpression.add 5074 5077, FieldExpression.sub 573 5049, FieldExpression.sub 574 5060, FieldExpression.sub 575 5071, FieldExpression.sub 576 5082] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_159 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5088
      ([FieldExpression.sub 577 5048, FieldExpression.sub 578 5059, FieldExpression.sub 579 5070, FieldExpression.sub 580 5081, FieldExpression.sub 581 5050, FieldExpression.sub 582 5061, FieldExpression.sub 583 5072, FieldExpression.sub 584 5083, FieldExpression.sub 585 5046, FieldExpression.sub 586 5057, FieldExpression.sub 587 5068, FieldExpression.sub 588 5079, FieldExpression.add 589 590, FieldExpression.add 591 5100, FieldExpression.add 592 5101, FieldExpression.add 589 5102, FieldExpression.add 590 5102, FieldExpression.add 591 5102, FieldExpression.add 592 5102, FieldExpression.add 593 594, FieldExpression.add 595 5107, FieldExpression.add 596 5108, FieldExpression.add 593 5109, FieldExpression.add 594 5109, FieldExpression.add 595 5109, FieldExpression.add 596 5109, FieldExpression.add 597 598, FieldExpression.add 599 5114, FieldExpression.add 600 5115, FieldExpression.add 597 5116, FieldExpression.add 598 5116, FieldExpression.add 599 5116] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_160 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5120
      ([FieldExpression.add 600 5116, FieldExpression.add 601 602, FieldExpression.add 603 5121, FieldExpression.add 604 5122, FieldExpression.add 601 5123, FieldExpression.add 602 5123, FieldExpression.add 603 5123, FieldExpression.add 604 5123, FieldExpression.add 5103 5110, FieldExpression.add 5117 5124, FieldExpression.add 5128 5129, FieldExpression.add 5110 5130, FieldExpression.add 5124 5130, FieldExpression.add 5103 5103, FieldExpression.add 5132 5133, FieldExpression.add 5117 5117, FieldExpression.add 5131 5135, FieldExpression.add 5128 5131, FieldExpression.add 5129 5132, FieldExpression.add 5104 5111, FieldExpression.add 5118 5125, FieldExpression.add 5139 5140, FieldExpression.add 5111 5141, FieldExpression.add 5125 5141, FieldExpression.add 5104 5104, FieldExpression.add 5143 5144, FieldExpression.add 5118 5118, FieldExpression.add 5142 5146, FieldExpression.add 5139 5142, FieldExpression.add 5140 5143, FieldExpression.add 5105 5112, FieldExpression.add 5119 5126] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_161 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5152
      ([FieldExpression.add 5150 5151, FieldExpression.add 5112 5152, FieldExpression.add 5126 5152, FieldExpression.add 5105 5105, FieldExpression.add 5154 5155, FieldExpression.add 5119 5119, FieldExpression.add 5153 5157, FieldExpression.add 5150 5153, FieldExpression.add 5151 5154, FieldExpression.add 5106 5113, FieldExpression.add 5120 5127, FieldExpression.add 5161 5162, FieldExpression.add 5113 5163, FieldExpression.add 5127 5163, FieldExpression.add 5106 5106, FieldExpression.add 5165 5166, FieldExpression.add 5120 5120, FieldExpression.add 5164 5168, FieldExpression.add 5161 5164, FieldExpression.add 5162 5165, FieldExpression.add 2108 5137, FieldExpression.sub 605 5172, FieldExpression.sub 605 2108, FieldExpression.add 2112 5148, FieldExpression.sub 606 5175, FieldExpression.sub 606 2112, FieldExpression.add 2116 5159, FieldExpression.sub 607 5178, FieldExpression.sub 607 2116, FieldExpression.add 2120 5170, FieldExpression.sub 608 5181, FieldExpression.sub 608 2120] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_162 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5184
      ([FieldExpression.add 2124 5136, FieldExpression.sub 609 5184, FieldExpression.sub 609 2124, FieldExpression.add 2128 5147, FieldExpression.sub 610 5187, FieldExpression.sub 610 2128, FieldExpression.add 2132 5158, FieldExpression.sub 611 5190, FieldExpression.sub 611 2132, FieldExpression.add 2136 5169, FieldExpression.sub 612 5193, FieldExpression.sub 612 2136, FieldExpression.add 2140 5138, FieldExpression.sub 613 5196, FieldExpression.sub 613 2140, FieldExpression.add 2144 5149, FieldExpression.sub 614 5199, FieldExpression.sub 614 2144, FieldExpression.add 2148 5160, FieldExpression.sub 615 5202, FieldExpression.sub 615 2148, FieldExpression.add 2152 5171, FieldExpression.sub 616 5205, FieldExpression.sub 616 2152, FieldExpression.add 2156 5134, FieldExpression.sub 617 5208, FieldExpression.sub 617 2156, FieldExpression.add 2160 5145, FieldExpression.sub 618 5211, FieldExpression.sub 618 2160, FieldExpression.add 2164 5156, FieldExpression.sub 619 5214] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_163 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5216
      ([FieldExpression.sub 619 2164, FieldExpression.add 2168 5167, FieldExpression.sub 620 5217, FieldExpression.sub 620 2168, FieldExpression.add 2108 5174, FieldExpression.mul 5220 5220, FieldExpression.mul 5221 5221, FieldExpression.mul 5221 5222, FieldExpression.mul 5220 5223, FieldExpression.add 2112 5177, FieldExpression.mul 5225 5225, FieldExpression.mul 5226 5226, FieldExpression.mul 5226 5227, FieldExpression.mul 5225 5228, FieldExpression.add 2116 5180, FieldExpression.mul 5230 5230, FieldExpression.mul 5231 5231, FieldExpression.mul 5231 5232, FieldExpression.mul 5230 5233, FieldExpression.add 2120 5183, FieldExpression.mul 5235 5235, FieldExpression.mul 5236 5236, FieldExpression.mul 5236 5237, FieldExpression.mul 5235 5238, FieldExpression.add 2124 5186, FieldExpression.mul 5240 5240, FieldExpression.mul 5241 5241, FieldExpression.mul 5241 5242, FieldExpression.mul 5240 5243, FieldExpression.add 2128 5189, FieldExpression.mul 5245 5245, FieldExpression.mul 5246 5246] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_164 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5248
      ([FieldExpression.mul 5246 5247, FieldExpression.mul 5245 5248, FieldExpression.add 2132 5192, FieldExpression.mul 5250 5250, FieldExpression.mul 5251 5251, FieldExpression.mul 5251 5252, FieldExpression.mul 5250 5253, FieldExpression.add 2136 5195, FieldExpression.mul 5255 5255, FieldExpression.mul 5256 5256, FieldExpression.mul 5256 5257, FieldExpression.mul 5255 5258, FieldExpression.add 2140 5198, FieldExpression.mul 5260 5260, FieldExpression.mul 5261 5261, FieldExpression.mul 5261 5262, FieldExpression.mul 5260 5263, FieldExpression.add 2144 5201, FieldExpression.mul 5265 5265, FieldExpression.mul 5266 5266, FieldExpression.mul 5266 5267, FieldExpression.mul 5265 5268, FieldExpression.add 2148 5204, FieldExpression.mul 5270 5270, FieldExpression.mul 5271 5271, FieldExpression.mul 5271 5272, FieldExpression.mul 5270 5273, FieldExpression.add 2152 5207, FieldExpression.mul 5275 5275, FieldExpression.mul 5276 5276, FieldExpression.mul 5276 5277, FieldExpression.mul 5275 5278] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_165 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5280
      ([FieldExpression.add 2156 5210, FieldExpression.mul 5280 5280, FieldExpression.mul 5281 5281, FieldExpression.mul 5281 5282, FieldExpression.mul 5280 5283, FieldExpression.add 2160 5213, FieldExpression.mul 5285 5285, FieldExpression.mul 5286 5286, FieldExpression.mul 5286 5287, FieldExpression.mul 5285 5288, FieldExpression.add 2164 5216, FieldExpression.mul 5290 5290, FieldExpression.mul 5291 5291, FieldExpression.mul 5291 5292, FieldExpression.mul 5290 5293, FieldExpression.add 2168 5219, FieldExpression.mul 5295 5295, FieldExpression.mul 5296 5296, FieldExpression.mul 5296 5297, FieldExpression.mul 5295 5298, FieldExpression.add 5224 5229, FieldExpression.add 5234 5300, FieldExpression.add 5239 5301, FieldExpression.add 5224 5302, FieldExpression.add 5229 5302, FieldExpression.add 5234 5302, FieldExpression.add 5239 5302, FieldExpression.add 5244 5249, FieldExpression.add 5254 5307, FieldExpression.add 5259 5308, FieldExpression.add 5244 5309, FieldExpression.add 5249 5309] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_166 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5312
      ([FieldExpression.add 5254 5309, FieldExpression.add 5259 5309, FieldExpression.add 5264 5269, FieldExpression.add 5274 5314, FieldExpression.add 5279 5315, FieldExpression.add 5264 5316, FieldExpression.add 5269 5316, FieldExpression.add 5274 5316, FieldExpression.add 5279 5316, FieldExpression.add 5284 5289, FieldExpression.add 5294 5321, FieldExpression.add 5299 5322, FieldExpression.add 5284 5323, FieldExpression.add 5289 5323, FieldExpression.add 5294 5323, FieldExpression.add 5299 5323, FieldExpression.add 5303 5310, FieldExpression.add 5317 5324, FieldExpression.add 5328 5329, FieldExpression.add 5310 5330, FieldExpression.add 5324 5330, FieldExpression.add 5303 5303, FieldExpression.add 5332 5333, FieldExpression.add 5317 5317, FieldExpression.add 5331 5335, FieldExpression.add 5328 5331, FieldExpression.add 5329 5332, FieldExpression.add 5304 5311, FieldExpression.add 5318 5325, FieldExpression.add 5339 5340, FieldExpression.add 5311 5341, FieldExpression.add 5325 5341] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_167 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5344
      ([FieldExpression.add 5304 5304, FieldExpression.add 5343 5344, FieldExpression.add 5318 5318, FieldExpression.add 5342 5346, FieldExpression.add 5339 5342, FieldExpression.add 5340 5343, FieldExpression.add 5305 5312, FieldExpression.add 5319 5326, FieldExpression.add 5350 5351, FieldExpression.add 5312 5352, FieldExpression.add 5326 5352, FieldExpression.add 5305 5305, FieldExpression.add 5354 5355, FieldExpression.add 5319 5319, FieldExpression.add 5353 5357, FieldExpression.add 5350 5353, FieldExpression.add 5351 5354, FieldExpression.add 5306 5313, FieldExpression.add 5320 5327, FieldExpression.add 5361 5362, FieldExpression.add 5313 5363, FieldExpression.add 5327 5363, FieldExpression.add 5306 5306, FieldExpression.add 5365 5366, FieldExpression.add 5320 5320, FieldExpression.add 5364 5368, FieldExpression.add 5361 5364, FieldExpression.add 5362 5365, FieldExpression.add 2324 5337, FieldExpression.sub 621 5372, FieldExpression.sub 621 2324, FieldExpression.add 2328 5348] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_168 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5376
      ([FieldExpression.sub 622 5375, FieldExpression.sub 622 2328, FieldExpression.add 2332 5359, FieldExpression.sub 623 5378, FieldExpression.sub 623 2332, FieldExpression.add 2336 5370, FieldExpression.sub 624 5381, FieldExpression.sub 624 2336, FieldExpression.add 2340 5336, FieldExpression.sub 625 5384, FieldExpression.sub 625 2340, FieldExpression.add 2344 5347, FieldExpression.sub 626 5387, FieldExpression.sub 626 2344, FieldExpression.add 2348 5358, FieldExpression.sub 627 5390, FieldExpression.sub 627 2348, FieldExpression.add 2352 5369, FieldExpression.sub 628 5393, FieldExpression.sub 628 2352, FieldExpression.add 2356 5338, FieldExpression.sub 629 5396, FieldExpression.sub 629 2356, FieldExpression.add 2360 5349, FieldExpression.sub 630 5399, FieldExpression.sub 630 2360, FieldExpression.add 2364 5360, FieldExpression.sub 631 5402, FieldExpression.sub 631 2364, FieldExpression.add 2368 5371, FieldExpression.sub 632 5405, FieldExpression.sub 632 2368] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_169 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5408
      ([FieldExpression.add 2372 5334, FieldExpression.sub 633 5408, FieldExpression.sub 633 2372, FieldExpression.add 2376 5345, FieldExpression.sub 634 5411, FieldExpression.sub 634 2376, FieldExpression.add 2380 5356, FieldExpression.sub 635 5414, FieldExpression.sub 635 2380, FieldExpression.add 2384 5367, FieldExpression.sub 636 5417, FieldExpression.sub 636 2384, FieldExpression.add 2324 5374, FieldExpression.mul 5420 5420, FieldExpression.mul 5421 5421, FieldExpression.mul 5421 5422, FieldExpression.mul 5420 5423, FieldExpression.add 2328 5377, FieldExpression.mul 5425 5425, FieldExpression.mul 5426 5426, FieldExpression.mul 5426 5427, FieldExpression.mul 5425 5428, FieldExpression.add 2332 5380, FieldExpression.mul 5430 5430, FieldExpression.mul 5431 5431, FieldExpression.mul 5431 5432, FieldExpression.mul 5430 5433, FieldExpression.add 2336 5383, FieldExpression.mul 5435 5435, FieldExpression.mul 5436 5436, FieldExpression.mul 5436 5437, FieldExpression.mul 5435 5438] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_170 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5440
      ([FieldExpression.add 2340 5386, FieldExpression.mul 5440 5440, FieldExpression.mul 5441 5441, FieldExpression.mul 5441 5442, FieldExpression.mul 5440 5443, FieldExpression.add 2344 5389, FieldExpression.mul 5445 5445, FieldExpression.mul 5446 5446, FieldExpression.mul 5446 5447, FieldExpression.mul 5445 5448, FieldExpression.add 2348 5392, FieldExpression.mul 5450 5450, FieldExpression.mul 5451 5451, FieldExpression.mul 5451 5452, FieldExpression.mul 5450 5453, FieldExpression.add 2352 5395, FieldExpression.mul 5455 5455, FieldExpression.mul 5456 5456, FieldExpression.mul 5456 5457, FieldExpression.mul 5455 5458, FieldExpression.add 2356 5398, FieldExpression.mul 5460 5460, FieldExpression.mul 5461 5461, FieldExpression.mul 5461 5462, FieldExpression.mul 5460 5463, FieldExpression.add 2360 5401, FieldExpression.mul 5465 5465, FieldExpression.mul 5466 5466, FieldExpression.mul 5466 5467, FieldExpression.mul 5465 5468, FieldExpression.add 2364 5404, FieldExpression.mul 5470 5470] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_171 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5472
      ([FieldExpression.mul 5471 5471, FieldExpression.mul 5471 5472, FieldExpression.mul 5470 5473, FieldExpression.add 2368 5407, FieldExpression.mul 5475 5475, FieldExpression.mul 5476 5476, FieldExpression.mul 5476 5477, FieldExpression.mul 5475 5478, FieldExpression.add 2372 5410, FieldExpression.mul 5480 5480, FieldExpression.mul 5481 5481, FieldExpression.mul 5481 5482, FieldExpression.mul 5480 5483, FieldExpression.add 2376 5413, FieldExpression.mul 5485 5485, FieldExpression.mul 5486 5486, FieldExpression.mul 5486 5487, FieldExpression.mul 5485 5488, FieldExpression.add 2380 5416, FieldExpression.mul 5490 5490, FieldExpression.mul 5491 5491, FieldExpression.mul 5491 5492, FieldExpression.mul 5490 5493, FieldExpression.add 2384 5419, FieldExpression.mul 5495 5495, FieldExpression.mul 5496 5496, FieldExpression.mul 5496 5497, FieldExpression.mul 5495 5498, FieldExpression.add 5424 5429, FieldExpression.add 5434 5500, FieldExpression.add 5439 5501, FieldExpression.add 5424 5502] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_172 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5504
      ([FieldExpression.add 5429 5502, FieldExpression.add 5434 5502, FieldExpression.add 5439 5502, FieldExpression.add 5444 5449, FieldExpression.add 5454 5507, FieldExpression.add 5459 5508, FieldExpression.add 5444 5509, FieldExpression.add 5449 5509, FieldExpression.add 5454 5509, FieldExpression.add 5459 5509, FieldExpression.add 5464 5469, FieldExpression.add 5474 5514, FieldExpression.add 5479 5515, FieldExpression.add 5464 5516, FieldExpression.add 5469 5516, FieldExpression.add 5474 5516, FieldExpression.add 5479 5516, FieldExpression.add 5484 5489, FieldExpression.add 5494 5521, FieldExpression.add 5499 5522, FieldExpression.add 5484 5523, FieldExpression.add 5489 5523, FieldExpression.add 5494 5523, FieldExpression.add 5499 5523, FieldExpression.add 5503 5510, FieldExpression.add 5517 5524, FieldExpression.add 5528 5529, FieldExpression.add 5510 5530, FieldExpression.add 5524 5530, FieldExpression.add 5503 5503, FieldExpression.add 5532 5533, FieldExpression.add 5517 5517] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_173 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5536
      ([FieldExpression.add 5531 5535, FieldExpression.add 5528 5531, FieldExpression.add 5529 5532, FieldExpression.add 5504 5511, FieldExpression.add 5518 5525, FieldExpression.add 5539 5540, FieldExpression.add 5511 5541, FieldExpression.add 5525 5541, FieldExpression.add 5504 5504, FieldExpression.add 5543 5544, FieldExpression.add 5518 5518, FieldExpression.add 5542 5546, FieldExpression.add 5539 5542, FieldExpression.add 5540 5543, FieldExpression.add 5505 5512, FieldExpression.add 5519 5526, FieldExpression.add 5550 5551, FieldExpression.add 5512 5552, FieldExpression.add 5526 5552, FieldExpression.add 5505 5505, FieldExpression.add 5554 5555, FieldExpression.add 5519 5519, FieldExpression.add 5553 5557, FieldExpression.add 5550 5553, FieldExpression.add 5551 5554, FieldExpression.add 5506 5513, FieldExpression.add 5520 5527, FieldExpression.add 5561 5562, FieldExpression.add 5513 5563, FieldExpression.add 5527 5563, FieldExpression.add 5506 5506, FieldExpression.add 5565 5566] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_174 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5568
      ([FieldExpression.add 5520 5520, FieldExpression.add 5564 5568, FieldExpression.add 5561 5564, FieldExpression.add 5562 5565, FieldExpression.add 2540 5537, FieldExpression.sub 637 5572, FieldExpression.sub 637 2540, FieldExpression.add 2544 5548, FieldExpression.sub 638 5575, FieldExpression.sub 638 2544, FieldExpression.add 2548 5559, FieldExpression.sub 639 5578, FieldExpression.sub 639 2548, FieldExpression.add 2552 5570, FieldExpression.sub 640 5581, FieldExpression.sub 640 2552, FieldExpression.add 2556 5536, FieldExpression.sub 641 5584, FieldExpression.sub 641 2556, FieldExpression.add 2560 5547, FieldExpression.sub 642 5587, FieldExpression.sub 642 2560, FieldExpression.add 2564 5558, FieldExpression.sub 643 5590, FieldExpression.sub 643 2564, FieldExpression.add 2568 5569, FieldExpression.sub 644 5593, FieldExpression.sub 644 2568, FieldExpression.add 2572 5538, FieldExpression.sub 645 5596, FieldExpression.sub 645 2572, FieldExpression.add 2576 5549] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_175 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5600
      ([FieldExpression.sub 646 5599, FieldExpression.sub 646 2576, FieldExpression.add 2580 5560, FieldExpression.sub 647 5602, FieldExpression.sub 647 2580, FieldExpression.add 2584 5571, FieldExpression.sub 648 5605, FieldExpression.sub 648 2584, FieldExpression.add 2588 5534, FieldExpression.sub 649 5608, FieldExpression.sub 649 2588, FieldExpression.add 2592 5545, FieldExpression.sub 650 5611, FieldExpression.sub 650 2592, FieldExpression.add 2596 5556, FieldExpression.sub 651 5614, FieldExpression.sub 651 2596, FieldExpression.add 2600 5567, FieldExpression.sub 652 5617, FieldExpression.sub 652 2600, FieldExpression.add 2540 5574, FieldExpression.mul 5620 5620, FieldExpression.mul 5621 5621, FieldExpression.mul 5621 5622, FieldExpression.mul 5620 5623, FieldExpression.add 2544 5577, FieldExpression.mul 5625 5625, FieldExpression.mul 5626 5626, FieldExpression.mul 5626 5627, FieldExpression.mul 5625 5628, FieldExpression.add 2548 5580, FieldExpression.mul 5630 5630] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_176 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5632
      ([FieldExpression.mul 5631 5631, FieldExpression.mul 5631 5632, FieldExpression.mul 5630 5633, FieldExpression.add 2552 5583, FieldExpression.mul 5635 5635, FieldExpression.mul 5636 5636, FieldExpression.mul 5636 5637, FieldExpression.mul 5635 5638, FieldExpression.add 2556 5586, FieldExpression.mul 5640 5640, FieldExpression.mul 5641 5641, FieldExpression.mul 5641 5642, FieldExpression.mul 5640 5643, FieldExpression.add 2560 5589, FieldExpression.mul 5645 5645, FieldExpression.mul 5646 5646, FieldExpression.mul 5646 5647, FieldExpression.mul 5645 5648, FieldExpression.add 2564 5592, FieldExpression.mul 5650 5650, FieldExpression.mul 5651 5651, FieldExpression.mul 5651 5652, FieldExpression.mul 5650 5653, FieldExpression.add 2568 5595, FieldExpression.mul 5655 5655, FieldExpression.mul 5656 5656, FieldExpression.mul 5656 5657, FieldExpression.mul 5655 5658, FieldExpression.add 2572 5598, FieldExpression.mul 5660 5660, FieldExpression.mul 5661 5661, FieldExpression.mul 5661 5662] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_177 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5664
      ([FieldExpression.mul 5660 5663, FieldExpression.add 2576 5601, FieldExpression.mul 5665 5665, FieldExpression.mul 5666 5666, FieldExpression.mul 5666 5667, FieldExpression.mul 5665 5668, FieldExpression.add 2580 5604, FieldExpression.mul 5670 5670, FieldExpression.mul 5671 5671, FieldExpression.mul 5671 5672, FieldExpression.mul 5670 5673, FieldExpression.add 2584 5607, FieldExpression.mul 5675 5675, FieldExpression.mul 5676 5676, FieldExpression.mul 5676 5677, FieldExpression.mul 5675 5678, FieldExpression.add 2588 5610, FieldExpression.mul 5680 5680, FieldExpression.mul 5681 5681, FieldExpression.mul 5681 5682, FieldExpression.mul 5680 5683, FieldExpression.add 2592 5613, FieldExpression.mul 5685 5685, FieldExpression.mul 5686 5686, FieldExpression.mul 5686 5687, FieldExpression.mul 5685 5688, FieldExpression.add 2596 5616, FieldExpression.mul 5690 5690, FieldExpression.mul 5691 5691, FieldExpression.mul 5691 5692, FieldExpression.mul 5690 5693, FieldExpression.add 2600 5619] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_178 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5696
      ([FieldExpression.mul 5695 5695, FieldExpression.mul 5696 5696, FieldExpression.mul 5696 5697, FieldExpression.mul 5695 5698, FieldExpression.add 5624 5629, FieldExpression.add 5634 5700, FieldExpression.add 5639 5701, FieldExpression.add 5624 5702, FieldExpression.add 5629 5702, FieldExpression.add 5634 5702, FieldExpression.add 5639 5702, FieldExpression.add 5644 5649, FieldExpression.add 5654 5707, FieldExpression.add 5659 5708, FieldExpression.add 5644 5709, FieldExpression.add 5649 5709, FieldExpression.add 5654 5709, FieldExpression.add 5659 5709, FieldExpression.add 5664 5669, FieldExpression.add 5674 5714, FieldExpression.add 5679 5715, FieldExpression.add 5664 5716, FieldExpression.add 5669 5716, FieldExpression.add 5674 5716, FieldExpression.add 5679 5716, FieldExpression.add 5684 5689, FieldExpression.add 5694 5721, FieldExpression.add 5699 5722, FieldExpression.add 5684 5723, FieldExpression.add 5689 5723, FieldExpression.add 5694 5723, FieldExpression.add 5699 5723] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_179 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5728
      ([FieldExpression.add 5703 5710, FieldExpression.add 5717 5724, FieldExpression.add 5728 5729, FieldExpression.add 5710 5730, FieldExpression.add 5724 5730, FieldExpression.add 5703 5703, FieldExpression.add 5732 5733, FieldExpression.add 5717 5717, FieldExpression.add 5731 5735, FieldExpression.add 5728 5731, FieldExpression.add 5729 5732, FieldExpression.add 5704 5711, FieldExpression.add 5718 5725, FieldExpression.add 5739 5740, FieldExpression.add 5711 5741, FieldExpression.add 5725 5741, FieldExpression.add 5704 5704, FieldExpression.add 5743 5744, FieldExpression.add 5718 5718, FieldExpression.add 5742 5746, FieldExpression.add 5739 5742, FieldExpression.add 5740 5743, FieldExpression.add 5705 5712, FieldExpression.add 5719 5726, FieldExpression.add 5750 5751, FieldExpression.add 5712 5752, FieldExpression.add 5726 5752, FieldExpression.add 5705 5705, FieldExpression.add 5754 5755, FieldExpression.add 5719 5719, FieldExpression.add 5753 5757, FieldExpression.add 5750 5753] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_180 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5760
      ([FieldExpression.add 5751 5754, FieldExpression.add 5706 5713, FieldExpression.add 5720 5727, FieldExpression.add 5761 5762, FieldExpression.add 5713 5763, FieldExpression.add 5727 5763, FieldExpression.add 5706 5706, FieldExpression.add 5765 5766, FieldExpression.add 5720 5720, FieldExpression.add 5764 5768, FieldExpression.add 5761 5764, FieldExpression.add 5762 5765, FieldExpression.add 2756 5737, FieldExpression.sub 653 5772, FieldExpression.sub 653 2756, FieldExpression.add 2760 5748, FieldExpression.sub 654 5775, FieldExpression.sub 654 2760, FieldExpression.add 2764 5759, FieldExpression.sub 655 5778, FieldExpression.sub 655 2764, FieldExpression.add 2768 5770, FieldExpression.sub 656 5781, FieldExpression.sub 656 2768, FieldExpression.add 2772 5736, FieldExpression.sub 657 5784, FieldExpression.sub 657 2772, FieldExpression.add 2776 5747, FieldExpression.sub 658 5787, FieldExpression.sub 658 2776, FieldExpression.add 2780 5758, FieldExpression.sub 659 5790] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_181 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5792
      ([FieldExpression.sub 659 2780, FieldExpression.add 2784 5769, FieldExpression.sub 660 5793, FieldExpression.sub 660 2784, FieldExpression.add 2788 5738, FieldExpression.sub 661 5796, FieldExpression.sub 661 2788, FieldExpression.add 2792 5749, FieldExpression.sub 662 5799, FieldExpression.sub 662 2792, FieldExpression.add 2796 5760, FieldExpression.sub 663 5802, FieldExpression.sub 663 2796, FieldExpression.add 2800 5771, FieldExpression.sub 664 5805, FieldExpression.sub 664 2800, FieldExpression.add 2804 5734, FieldExpression.sub 665 5808, FieldExpression.sub 665 2804, FieldExpression.add 2808 5745, FieldExpression.sub 666 5811, FieldExpression.sub 666 2808, FieldExpression.add 2812 5756, FieldExpression.sub 667 5814, FieldExpression.sub 667 2812, FieldExpression.add 2816 5767, FieldExpression.sub 668 5817, FieldExpression.sub 668 2816, FieldExpression.add 2756 5774, FieldExpression.mul 5820 5820, FieldExpression.mul 5821 5821, FieldExpression.mul 5821 5822] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_182 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5824
      ([FieldExpression.mul 5820 5823, FieldExpression.add 2760 5777, FieldExpression.mul 5825 5825, FieldExpression.mul 5826 5826, FieldExpression.mul 5826 5827, FieldExpression.mul 5825 5828, FieldExpression.add 2764 5780, FieldExpression.mul 5830 5830, FieldExpression.mul 5831 5831, FieldExpression.mul 5831 5832, FieldExpression.mul 5830 5833, FieldExpression.add 2768 5783, FieldExpression.mul 5835 5835, FieldExpression.mul 5836 5836, FieldExpression.mul 5836 5837, FieldExpression.mul 5835 5838, FieldExpression.add 2772 5786, FieldExpression.mul 5840 5840, FieldExpression.mul 5841 5841, FieldExpression.mul 5841 5842, FieldExpression.mul 5840 5843, FieldExpression.add 2776 5789, FieldExpression.mul 5845 5845, FieldExpression.mul 5846 5846, FieldExpression.mul 5846 5847, FieldExpression.mul 5845 5848, FieldExpression.add 2780 5792, FieldExpression.mul 5850 5850, FieldExpression.mul 5851 5851, FieldExpression.mul 5851 5852, FieldExpression.mul 5850 5853, FieldExpression.add 2784 5795] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_183 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5856
      ([FieldExpression.mul 5855 5855, FieldExpression.mul 5856 5856, FieldExpression.mul 5856 5857, FieldExpression.mul 5855 5858, FieldExpression.add 2788 5798, FieldExpression.mul 5860 5860, FieldExpression.mul 5861 5861, FieldExpression.mul 5861 5862, FieldExpression.mul 5860 5863, FieldExpression.add 2792 5801, FieldExpression.mul 5865 5865, FieldExpression.mul 5866 5866, FieldExpression.mul 5866 5867, FieldExpression.mul 5865 5868, FieldExpression.add 2796 5804, FieldExpression.mul 5870 5870, FieldExpression.mul 5871 5871, FieldExpression.mul 5871 5872, FieldExpression.mul 5870 5873, FieldExpression.add 2800 5807, FieldExpression.mul 5875 5875, FieldExpression.mul 5876 5876, FieldExpression.mul 5876 5877, FieldExpression.mul 5875 5878, FieldExpression.add 2804 5810, FieldExpression.mul 5880 5880, FieldExpression.mul 5881 5881, FieldExpression.mul 5881 5882, FieldExpression.mul 5880 5883, FieldExpression.add 2808 5813, FieldExpression.mul 5885 5885, FieldExpression.mul 5886 5886] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_184 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5888
      ([FieldExpression.mul 5886 5887, FieldExpression.mul 5885 5888, FieldExpression.add 2812 5816, FieldExpression.mul 5890 5890, FieldExpression.mul 5891 5891, FieldExpression.mul 5891 5892, FieldExpression.mul 5890 5893, FieldExpression.add 2816 5819, FieldExpression.mul 5895 5895, FieldExpression.mul 5896 5896, FieldExpression.mul 5896 5897, FieldExpression.mul 5895 5898, FieldExpression.add 5824 5829, FieldExpression.add 5834 5900, FieldExpression.add 5839 5901, FieldExpression.add 5824 5902, FieldExpression.add 5829 5902, FieldExpression.add 5834 5902, FieldExpression.add 5839 5902, FieldExpression.add 5844 5849, FieldExpression.add 5854 5907, FieldExpression.add 5859 5908, FieldExpression.add 5844 5909, FieldExpression.add 5849 5909, FieldExpression.add 5854 5909, FieldExpression.add 5859 5909, FieldExpression.add 5864 5869, FieldExpression.add 5874 5914, FieldExpression.add 5879 5915, FieldExpression.add 5864 5916, FieldExpression.add 5869 5916, FieldExpression.add 5874 5916] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_185 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5920
      ([FieldExpression.add 5879 5916, FieldExpression.add 5884 5889, FieldExpression.add 5894 5921, FieldExpression.add 5899 5922, FieldExpression.add 5884 5923, FieldExpression.add 5889 5923, FieldExpression.add 5894 5923, FieldExpression.add 5899 5923, FieldExpression.add 5903 5910, FieldExpression.add 5917 5924, FieldExpression.add 5928 5929, FieldExpression.add 5910 5930, FieldExpression.add 5924 5930, FieldExpression.add 5903 5903, FieldExpression.add 5932 5933, FieldExpression.add 5917 5917, FieldExpression.add 5931 5935, FieldExpression.add 5928 5931, FieldExpression.add 5929 5932, FieldExpression.add 5904 5911, FieldExpression.add 5918 5925, FieldExpression.add 5939 5940, FieldExpression.add 5911 5941, FieldExpression.add 5925 5941, FieldExpression.add 5904 5904, FieldExpression.add 5943 5944, FieldExpression.add 5918 5918, FieldExpression.add 5942 5946, FieldExpression.add 5939 5942, FieldExpression.add 5940 5943, FieldExpression.add 5905 5912, FieldExpression.add 5919 5926] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_186 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5952
      ([FieldExpression.add 5950 5951, FieldExpression.add 5912 5952, FieldExpression.add 5926 5952, FieldExpression.add 5905 5905, FieldExpression.add 5954 5955, FieldExpression.add 5919 5919, FieldExpression.add 5953 5957, FieldExpression.add 5950 5953, FieldExpression.add 5951 5954, FieldExpression.add 5906 5913, FieldExpression.add 5920 5927, FieldExpression.add 5961 5962, FieldExpression.add 5913 5963, FieldExpression.add 5927 5963, FieldExpression.add 5906 5906, FieldExpression.add 5965 5966, FieldExpression.add 5920 5920, FieldExpression.add 5964 5968, FieldExpression.add 5961 5964, FieldExpression.add 5962 5965, FieldExpression.add 2972 5937, FieldExpression.sub 669 5972, FieldExpression.sub 669 2972, FieldExpression.add 2972 5974, FieldExpression.mul 5975 5975, FieldExpression.mul 5976 5976, FieldExpression.mul 5976 5977, FieldExpression.mul 5975 5978, FieldExpression.add 5948 5979, FieldExpression.add 5959 5980, FieldExpression.add 5970 5981, FieldExpression.add 5936 5982] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_187 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 5984
      ([FieldExpression.add 5947 5983, FieldExpression.add 5958 5984, FieldExpression.add 5969 5985, FieldExpression.add 5938 5986, FieldExpression.add 5949 5987, FieldExpression.add 5960 5988, FieldExpression.add 5971 5989, FieldExpression.add 5934 5990, FieldExpression.add 5945 5991, FieldExpression.add 5956 5992, FieldExpression.add 5967 5993, FieldExpression.mul 2996 5979, FieldExpression.add 5994 5995, FieldExpression.mul 2999 5948, FieldExpression.add 5994 5997, FieldExpression.mul 3002 5959, FieldExpression.add 5994 5999, FieldExpression.mul 3005 5970, FieldExpression.add 5994 6001, FieldExpression.mul 3008 5936, FieldExpression.add 5994 6003, FieldExpression.mul 3011 5947, FieldExpression.add 5994 6005, FieldExpression.mul 3014 5958, FieldExpression.add 5994 6007, FieldExpression.mul 3017 5969, FieldExpression.add 5994 6009, FieldExpression.mul 3020 5938, FieldExpression.add 5994 6011, FieldExpression.mul 3023 5949, FieldExpression.add 5994 6013, FieldExpression.mul 3026 5960] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_188 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6016
      ([FieldExpression.add 5994 6015, FieldExpression.mul 3029 5971, FieldExpression.add 5994 6017, FieldExpression.mul 3032 5934, FieldExpression.add 5994 6019, FieldExpression.mul 3035 5945, FieldExpression.add 5994 6021, FieldExpression.mul 3038 5956, FieldExpression.add 5994 6023, FieldExpression.mul 3041 5967, FieldExpression.add 5994 6025, FieldExpression.add 3044 5996, FieldExpression.sub 670 6027, FieldExpression.sub 670 3044, FieldExpression.add 3044 6029, FieldExpression.mul 6030 6030, FieldExpression.mul 6031 6031, FieldExpression.mul 6031 6032, FieldExpression.mul 6030 6033, FieldExpression.add 5998 6034, FieldExpression.add 6000 6035, FieldExpression.add 6002 6036, FieldExpression.add 6004 6037, FieldExpression.add 6006 6038, FieldExpression.add 6008 6039, FieldExpression.add 6010 6040, FieldExpression.add 6012 6041, FieldExpression.add 6014 6042, FieldExpression.add 6016 6043, FieldExpression.add 6018 6044, FieldExpression.add 6020 6045, FieldExpression.add 6022 6046] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_189 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6048
      ([FieldExpression.add 6024 6047, FieldExpression.add 6026 6048, FieldExpression.mul 2996 6034, FieldExpression.add 6049 6050, FieldExpression.mul 2999 5998, FieldExpression.add 6049 6052, FieldExpression.mul 3002 6000, FieldExpression.add 6049 6054, FieldExpression.mul 3005 6002, FieldExpression.add 6049 6056, FieldExpression.mul 3008 6004, FieldExpression.add 6049 6058, FieldExpression.mul 3011 6006, FieldExpression.add 6049 6060, FieldExpression.mul 3014 6008, FieldExpression.add 6049 6062, FieldExpression.mul 3017 6010, FieldExpression.add 6049 6064, FieldExpression.mul 3020 6012, FieldExpression.add 6049 6066, FieldExpression.mul 3023 6014, FieldExpression.add 6049 6068, FieldExpression.mul 3026 6016, FieldExpression.add 6049 6070, FieldExpression.mul 3029 6018, FieldExpression.add 6049 6072, FieldExpression.mul 3032 6020, FieldExpression.add 6049 6074, FieldExpression.mul 3035 6022, FieldExpression.add 6049 6076, FieldExpression.mul 3038 6024, FieldExpression.add 6049 6078] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_190 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6080
      ([FieldExpression.mul 3041 6026, FieldExpression.add 6049 6080, FieldExpression.add 3100 6051, FieldExpression.sub 671 6082, FieldExpression.sub 671 3100, FieldExpression.add 3100 6084, FieldExpression.mul 6085 6085, FieldExpression.mul 6086 6086, FieldExpression.mul 6086 6087, FieldExpression.mul 6085 6088, FieldExpression.add 6053 6089, FieldExpression.add 6055 6090, FieldExpression.add 6057 6091, FieldExpression.add 6059 6092, FieldExpression.add 6061 6093, FieldExpression.add 6063 6094, FieldExpression.add 6065 6095, FieldExpression.add 6067 6096, FieldExpression.add 6069 6097, FieldExpression.add 6071 6098, FieldExpression.add 6073 6099, FieldExpression.add 6075 6100, FieldExpression.add 6077 6101, FieldExpression.add 6079 6102, FieldExpression.add 6081 6103, FieldExpression.mul 2996 6089, FieldExpression.add 6104 6105, FieldExpression.mul 2999 6053, FieldExpression.add 6104 6107, FieldExpression.mul 3002 6055, FieldExpression.add 6104 6109, FieldExpression.mul 3005 6057] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_191 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6112
      ([FieldExpression.add 6104 6111, FieldExpression.mul 3008 6059, FieldExpression.add 6104 6113, FieldExpression.mul 3011 6061, FieldExpression.add 6104 6115, FieldExpression.mul 3014 6063, FieldExpression.add 6104 6117, FieldExpression.mul 3017 6065, FieldExpression.add 6104 6119, FieldExpression.mul 3020 6067, FieldExpression.add 6104 6121, FieldExpression.mul 3023 6069, FieldExpression.add 6104 6123, FieldExpression.mul 3026 6071, FieldExpression.add 6104 6125, FieldExpression.mul 3029 6073, FieldExpression.add 6104 6127, FieldExpression.mul 3032 6075, FieldExpression.add 6104 6129, FieldExpression.mul 3035 6077, FieldExpression.add 6104 6131, FieldExpression.mul 3038 6079, FieldExpression.add 6104 6133, FieldExpression.mul 3041 6081, FieldExpression.add 6104 6135, FieldExpression.add 3156 6106, FieldExpression.sub 672 6137, FieldExpression.sub 672 3156, FieldExpression.add 3156 6139, FieldExpression.mul 6140 6140, FieldExpression.mul 6141 6141, FieldExpression.mul 6141 6142] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_192 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6144
      ([FieldExpression.mul 6140 6143, FieldExpression.add 6108 6144, FieldExpression.add 6110 6145, FieldExpression.add 6112 6146, FieldExpression.add 6114 6147, FieldExpression.add 6116 6148, FieldExpression.add 6118 6149, FieldExpression.add 6120 6150, FieldExpression.add 6122 6151, FieldExpression.add 6124 6152, FieldExpression.add 6126 6153, FieldExpression.add 6128 6154, FieldExpression.add 6130 6155, FieldExpression.add 6132 6156, FieldExpression.add 6134 6157, FieldExpression.add 6136 6158, FieldExpression.mul 2996 6144, FieldExpression.add 6159 6160, FieldExpression.mul 2999 6108, FieldExpression.add 6159 6162, FieldExpression.mul 3002 6110, FieldExpression.add 6159 6164, FieldExpression.mul 3005 6112, FieldExpression.add 6159 6166, FieldExpression.mul 3008 6114, FieldExpression.add 6159 6168, FieldExpression.mul 3011 6116, FieldExpression.add 6159 6170, FieldExpression.mul 3014 6118, FieldExpression.add 6159 6172, FieldExpression.mul 3017 6120, FieldExpression.add 6159 6174] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_193 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6176
      ([FieldExpression.mul 3020 6122, FieldExpression.add 6159 6176, FieldExpression.mul 3023 6124, FieldExpression.add 6159 6178, FieldExpression.mul 3026 6126, FieldExpression.add 6159 6180, FieldExpression.mul 3029 6128, FieldExpression.add 6159 6182, FieldExpression.mul 3032 6130, FieldExpression.add 6159 6184, FieldExpression.mul 3035 6132, FieldExpression.add 6159 6186, FieldExpression.mul 3038 6134, FieldExpression.add 6159 6188, FieldExpression.mul 3041 6136, FieldExpression.add 6159 6190, FieldExpression.add 3212 6161, FieldExpression.sub 673 6192, FieldExpression.sub 673 3212, FieldExpression.add 3212 6194, FieldExpression.mul 6195 6195, FieldExpression.mul 6196 6196, FieldExpression.mul 6196 6197, FieldExpression.mul 6195 6198, FieldExpression.add 6163 6199, FieldExpression.add 6165 6200, FieldExpression.add 6167 6201, FieldExpression.add 6169 6202, FieldExpression.add 6171 6203, FieldExpression.add 6173 6204, FieldExpression.add 6175 6205, FieldExpression.add 6177 6206] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_194 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6208
      ([FieldExpression.add 6179 6207, FieldExpression.add 6181 6208, FieldExpression.add 6183 6209, FieldExpression.add 6185 6210, FieldExpression.add 6187 6211, FieldExpression.add 6189 6212, FieldExpression.add 6191 6213, FieldExpression.mul 2996 6199, FieldExpression.add 6214 6215, FieldExpression.mul 2999 6163, FieldExpression.add 6214 6217, FieldExpression.mul 3002 6165, FieldExpression.add 6214 6219, FieldExpression.mul 3005 6167, FieldExpression.add 6214 6221, FieldExpression.mul 3008 6169, FieldExpression.add 6214 6223, FieldExpression.mul 3011 6171, FieldExpression.add 6214 6225, FieldExpression.mul 3014 6173, FieldExpression.add 6214 6227, FieldExpression.mul 3017 6175, FieldExpression.add 6214 6229, FieldExpression.mul 3020 6177, FieldExpression.add 6214 6231, FieldExpression.mul 3023 6179, FieldExpression.add 6214 6233, FieldExpression.mul 3026 6181, FieldExpression.add 6214 6235, FieldExpression.mul 3029 6183, FieldExpression.add 6214 6237, FieldExpression.mul 3032 6185] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_195 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6240
      ([FieldExpression.add 6214 6239, FieldExpression.mul 3035 6187, FieldExpression.add 6214 6241, FieldExpression.mul 3038 6189, FieldExpression.add 6214 6243, FieldExpression.mul 3041 6191, FieldExpression.add 6214 6245, FieldExpression.add 3268 6216, FieldExpression.sub 674 6247, FieldExpression.sub 674 3268, FieldExpression.add 3268 6249, FieldExpression.mul 6250 6250, FieldExpression.mul 6251 6251, FieldExpression.mul 6251 6252, FieldExpression.mul 6250 6253, FieldExpression.add 6218 6254, FieldExpression.add 6220 6255, FieldExpression.add 6222 6256, FieldExpression.add 6224 6257, FieldExpression.add 6226 6258, FieldExpression.add 6228 6259, FieldExpression.add 6230 6260, FieldExpression.add 6232 6261, FieldExpression.add 6234 6262, FieldExpression.add 6236 6263, FieldExpression.add 6238 6264, FieldExpression.add 6240 6265, FieldExpression.add 6242 6266, FieldExpression.add 6244 6267, FieldExpression.add 6246 6268, FieldExpression.mul 2996 6254, FieldExpression.add 6269 6270] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_196 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6272
      ([FieldExpression.mul 2999 6218, FieldExpression.add 6269 6272, FieldExpression.mul 3002 6220, FieldExpression.add 6269 6274, FieldExpression.mul 3005 6222, FieldExpression.add 6269 6276, FieldExpression.mul 3008 6224, FieldExpression.add 6269 6278, FieldExpression.mul 3011 6226, FieldExpression.add 6269 6280, FieldExpression.mul 3014 6228, FieldExpression.add 6269 6282, FieldExpression.mul 3017 6230, FieldExpression.add 6269 6284, FieldExpression.mul 3020 6232, FieldExpression.add 6269 6286, FieldExpression.mul 3023 6234, FieldExpression.add 6269 6288, FieldExpression.mul 3026 6236, FieldExpression.add 6269 6290, FieldExpression.mul 3029 6238, FieldExpression.add 6269 6292, FieldExpression.mul 3032 6240, FieldExpression.add 6269 6294, FieldExpression.mul 3035 6242, FieldExpression.add 6269 6296, FieldExpression.mul 3038 6244, FieldExpression.add 6269 6298, FieldExpression.mul 3041 6246, FieldExpression.add 6269 6300, FieldExpression.add 3324 6271, FieldExpression.sub 675 6302] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_197 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6304
      ([FieldExpression.sub 675 3324, FieldExpression.add 3324 6304, FieldExpression.mul 6305 6305, FieldExpression.mul 6306 6306, FieldExpression.mul 6306 6307, FieldExpression.mul 6305 6308, FieldExpression.add 6273 6309, FieldExpression.add 6275 6310, FieldExpression.add 6277 6311, FieldExpression.add 6279 6312, FieldExpression.add 6281 6313, FieldExpression.add 6283 6314, FieldExpression.add 6285 6315, FieldExpression.add 6287 6316, FieldExpression.add 6289 6317, FieldExpression.add 6291 6318, FieldExpression.add 6293 6319, FieldExpression.add 6295 6320, FieldExpression.add 6297 6321, FieldExpression.add 6299 6322, FieldExpression.add 6301 6323, FieldExpression.mul 2996 6309, FieldExpression.add 6324 6325, FieldExpression.mul 2999 6273, FieldExpression.add 6324 6327, FieldExpression.mul 3002 6275, FieldExpression.add 6324 6329, FieldExpression.mul 3005 6277, FieldExpression.add 6324 6331, FieldExpression.mul 3008 6279, FieldExpression.add 6324 6333, FieldExpression.mul 3011 6281] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_198 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6336
      ([FieldExpression.add 6324 6335, FieldExpression.mul 3014 6283, FieldExpression.add 6324 6337, FieldExpression.mul 3017 6285, FieldExpression.add 6324 6339, FieldExpression.mul 3020 6287, FieldExpression.add 6324 6341, FieldExpression.mul 3023 6289, FieldExpression.add 6324 6343, FieldExpression.mul 3026 6291, FieldExpression.add 6324 6345, FieldExpression.mul 3029 6293, FieldExpression.add 6324 6347, FieldExpression.mul 3032 6295, FieldExpression.add 6324 6349, FieldExpression.mul 3035 6297, FieldExpression.add 6324 6351, FieldExpression.mul 3038 6299, FieldExpression.add 6324 6353, FieldExpression.mul 3041 6301, FieldExpression.add 6324 6355, FieldExpression.add 3380 6326, FieldExpression.sub 676 6357, FieldExpression.sub 676 3380, FieldExpression.add 3380 6359, FieldExpression.mul 6360 6360, FieldExpression.mul 6361 6361, FieldExpression.mul 6361 6362, FieldExpression.mul 6360 6363, FieldExpression.add 6328 6364, FieldExpression.add 6330 6365, FieldExpression.add 6332 6366] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_199 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6368
      ([FieldExpression.add 6334 6367, FieldExpression.add 6336 6368, FieldExpression.add 6338 6369, FieldExpression.add 6340 6370, FieldExpression.add 6342 6371, FieldExpression.add 6344 6372, FieldExpression.add 6346 6373, FieldExpression.add 6348 6374, FieldExpression.add 6350 6375, FieldExpression.add 6352 6376, FieldExpression.add 6354 6377, FieldExpression.add 6356 6378, FieldExpression.mul 2996 6364, FieldExpression.add 6379 6380, FieldExpression.mul 2999 6328, FieldExpression.add 6379 6382, FieldExpression.mul 3002 6330, FieldExpression.add 6379 6384, FieldExpression.mul 3005 6332, FieldExpression.add 6379 6386, FieldExpression.mul 3008 6334, FieldExpression.add 6379 6388, FieldExpression.mul 3011 6336, FieldExpression.add 6379 6390, FieldExpression.mul 3014 6338, FieldExpression.add 6379 6392, FieldExpression.mul 3017 6340, FieldExpression.add 6379 6394, FieldExpression.mul 3020 6342, FieldExpression.add 6379 6396, FieldExpression.mul 3023 6344, FieldExpression.add 6379 6398] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_200 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6400
      ([FieldExpression.mul 3026 6346, FieldExpression.add 6379 6400, FieldExpression.mul 3029 6348, FieldExpression.add 6379 6402, FieldExpression.mul 3032 6350, FieldExpression.add 6379 6404, FieldExpression.mul 3035 6352, FieldExpression.add 6379 6406, FieldExpression.mul 3038 6354, FieldExpression.add 6379 6408, FieldExpression.mul 3041 6356, FieldExpression.add 6379 6410, FieldExpression.add 3436 6381, FieldExpression.sub 677 6412, FieldExpression.sub 677 3436, FieldExpression.add 3436 6414, FieldExpression.mul 6415 6415, FieldExpression.mul 6416 6416, FieldExpression.mul 6416 6417, FieldExpression.mul 6415 6418, FieldExpression.add 6383 6419, FieldExpression.add 6385 6420, FieldExpression.add 6387 6421, FieldExpression.add 6389 6422, FieldExpression.add 6391 6423, FieldExpression.add 6393 6424, FieldExpression.add 6395 6425, FieldExpression.add 6397 6426, FieldExpression.add 6399 6427, FieldExpression.add 6401 6428, FieldExpression.add 6403 6429, FieldExpression.add 6405 6430] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_201 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6432
      ([FieldExpression.add 6407 6431, FieldExpression.add 6409 6432, FieldExpression.add 6411 6433, FieldExpression.mul 2996 6419, FieldExpression.add 6434 6435, FieldExpression.mul 2999 6383, FieldExpression.add 6434 6437, FieldExpression.mul 3002 6385, FieldExpression.add 6434 6439, FieldExpression.mul 3005 6387, FieldExpression.add 6434 6441, FieldExpression.mul 3008 6389, FieldExpression.add 6434 6443, FieldExpression.mul 3011 6391, FieldExpression.add 6434 6445, FieldExpression.mul 3014 6393, FieldExpression.add 6434 6447, FieldExpression.mul 3017 6395, FieldExpression.add 6434 6449, FieldExpression.mul 3020 6397, FieldExpression.add 6434 6451, FieldExpression.mul 3023 6399, FieldExpression.add 6434 6453, FieldExpression.mul 3026 6401, FieldExpression.add 6434 6455, FieldExpression.mul 3029 6403, FieldExpression.add 6434 6457, FieldExpression.mul 3032 6405, FieldExpression.add 6434 6459, FieldExpression.mul 3035 6407, FieldExpression.add 6434 6461, FieldExpression.mul 3038 6409] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_202 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6464
      ([FieldExpression.add 6434 6463, FieldExpression.mul 3041 6411, FieldExpression.add 6434 6465, FieldExpression.add 3492 6436, FieldExpression.sub 678 6467, FieldExpression.sub 678 3492, FieldExpression.add 3492 6469, FieldExpression.mul 6470 6470, FieldExpression.mul 6471 6471, FieldExpression.mul 6471 6472, FieldExpression.mul 6470 6473, FieldExpression.add 6438 6474, FieldExpression.add 6440 6475, FieldExpression.add 6442 6476, FieldExpression.add 6444 6477, FieldExpression.add 6446 6478, FieldExpression.add 6448 6479, FieldExpression.add 6450 6480, FieldExpression.add 6452 6481, FieldExpression.add 6454 6482, FieldExpression.add 6456 6483, FieldExpression.add 6458 6484, FieldExpression.add 6460 6485, FieldExpression.add 6462 6486, FieldExpression.add 6464 6487, FieldExpression.add 6466 6488, FieldExpression.mul 2996 6474, FieldExpression.add 6489 6490, FieldExpression.mul 2999 6438, FieldExpression.add 6489 6492, FieldExpression.mul 3002 6440, FieldExpression.add 6489 6494] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_203 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6496
      ([FieldExpression.mul 3005 6442, FieldExpression.add 6489 6496, FieldExpression.mul 3008 6444, FieldExpression.add 6489 6498, FieldExpression.mul 3011 6446, FieldExpression.add 6489 6500, FieldExpression.mul 3014 6448, FieldExpression.add 6489 6502, FieldExpression.mul 3017 6450, FieldExpression.add 6489 6504, FieldExpression.mul 3020 6452, FieldExpression.add 6489 6506, FieldExpression.mul 3023 6454, FieldExpression.add 6489 6508, FieldExpression.mul 3026 6456, FieldExpression.add 6489 6510, FieldExpression.mul 3029 6458, FieldExpression.add 6489 6512, FieldExpression.mul 3032 6460, FieldExpression.add 6489 6514, FieldExpression.mul 3035 6462, FieldExpression.add 6489 6516, FieldExpression.mul 3038 6464, FieldExpression.add 6489 6518, FieldExpression.mul 3041 6466, FieldExpression.add 6489 6520, FieldExpression.add 3548 6491, FieldExpression.sub 679 6522, FieldExpression.sub 679 3548, FieldExpression.add 3548 6524, FieldExpression.mul 6525 6525, FieldExpression.mul 6526 6526] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_204 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6528
      ([FieldExpression.mul 6526 6527, FieldExpression.mul 6525 6528, FieldExpression.add 6493 6529, FieldExpression.add 6495 6530, FieldExpression.add 6497 6531, FieldExpression.add 6499 6532, FieldExpression.add 6501 6533, FieldExpression.add 6503 6534, FieldExpression.add 6505 6535, FieldExpression.add 6507 6536, FieldExpression.add 6509 6537, FieldExpression.add 6511 6538, FieldExpression.add 6513 6539, FieldExpression.add 6515 6540, FieldExpression.add 6517 6541, FieldExpression.add 6519 6542, FieldExpression.add 6521 6543, FieldExpression.mul 2996 6529, FieldExpression.add 6544 6545, FieldExpression.mul 2999 6493, FieldExpression.add 6544 6547, FieldExpression.mul 3002 6495, FieldExpression.add 6544 6549, FieldExpression.mul 3005 6497, FieldExpression.add 6544 6551, FieldExpression.mul 3008 6499, FieldExpression.add 6544 6553, FieldExpression.mul 3011 6501, FieldExpression.add 6544 6555, FieldExpression.mul 3014 6503, FieldExpression.add 6544 6557, FieldExpression.mul 3017 6505] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_205 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6560
      ([FieldExpression.add 6544 6559, FieldExpression.mul 3020 6507, FieldExpression.add 6544 6561, FieldExpression.mul 3023 6509, FieldExpression.add 6544 6563, FieldExpression.mul 3026 6511, FieldExpression.add 6544 6565, FieldExpression.mul 3029 6513, FieldExpression.add 6544 6567, FieldExpression.mul 3032 6515, FieldExpression.add 6544 6569, FieldExpression.mul 3035 6517, FieldExpression.add 6544 6571, FieldExpression.mul 3038 6519, FieldExpression.add 6544 6573, FieldExpression.mul 3041 6521, FieldExpression.add 6544 6575, FieldExpression.add 3604 6546, FieldExpression.sub 680 6577, FieldExpression.sub 680 3604, FieldExpression.add 3604 6579, FieldExpression.mul 6580 6580, FieldExpression.mul 6581 6581, FieldExpression.mul 6581 6582, FieldExpression.mul 6580 6583, FieldExpression.add 6548 6584, FieldExpression.add 6550 6585, FieldExpression.add 6552 6586, FieldExpression.add 6554 6587, FieldExpression.add 6556 6588, FieldExpression.add 6558 6589, FieldExpression.add 6560 6590] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_206 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6592
      ([FieldExpression.add 6562 6591, FieldExpression.add 6564 6592, FieldExpression.add 6566 6593, FieldExpression.add 6568 6594, FieldExpression.add 6570 6595, FieldExpression.add 6572 6596, FieldExpression.add 6574 6597, FieldExpression.add 6576 6598, FieldExpression.mul 2996 6584, FieldExpression.add 6599 6600, FieldExpression.mul 2999 6548, FieldExpression.add 6599 6602, FieldExpression.mul 3002 6550, FieldExpression.add 6599 6604, FieldExpression.mul 3005 6552, FieldExpression.add 6599 6606, FieldExpression.mul 3008 6554, FieldExpression.add 6599 6608, FieldExpression.mul 3011 6556, FieldExpression.add 6599 6610, FieldExpression.mul 3014 6558, FieldExpression.add 6599 6612, FieldExpression.mul 3017 6560, FieldExpression.add 6599 6614, FieldExpression.mul 3020 6562, FieldExpression.add 6599 6616, FieldExpression.mul 3023 6564, FieldExpression.add 6599 6618, FieldExpression.mul 3026 6566, FieldExpression.add 6599 6620, FieldExpression.mul 3029 6568, FieldExpression.add 6599 6622] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_207 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6624
      ([FieldExpression.mul 3032 6570, FieldExpression.add 6599 6624, FieldExpression.mul 3035 6572, FieldExpression.add 6599 6626, FieldExpression.mul 3038 6574, FieldExpression.add 6599 6628, FieldExpression.mul 3041 6576, FieldExpression.add 6599 6630, FieldExpression.add 3660 6601, FieldExpression.sub 681 6632, FieldExpression.sub 681 3660, FieldExpression.add 3660 6634, FieldExpression.mul 6635 6635, FieldExpression.mul 6636 6636, FieldExpression.mul 6636 6637, FieldExpression.mul 6635 6638, FieldExpression.add 6603 6639, FieldExpression.add 6605 6640, FieldExpression.add 6607 6641, FieldExpression.add 6609 6642, FieldExpression.add 6611 6643, FieldExpression.add 6613 6644, FieldExpression.add 6615 6645, FieldExpression.add 6617 6646, FieldExpression.add 6619 6647, FieldExpression.add 6621 6648, FieldExpression.add 6623 6649, FieldExpression.add 6625 6650, FieldExpression.add 6627 6651, FieldExpression.add 6629 6652, FieldExpression.add 6631 6653, FieldExpression.mul 2996 6639] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_208 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6656
      ([FieldExpression.add 6654 6655, FieldExpression.mul 2999 6603, FieldExpression.add 6654 6657, FieldExpression.mul 3002 6605, FieldExpression.add 6654 6659, FieldExpression.mul 3005 6607, FieldExpression.add 6654 6661, FieldExpression.mul 3008 6609, FieldExpression.add 6654 6663, FieldExpression.mul 3011 6611, FieldExpression.add 6654 6665, FieldExpression.mul 3014 6613, FieldExpression.add 6654 6667, FieldExpression.mul 3017 6615, FieldExpression.add 6654 6669, FieldExpression.mul 3020 6617, FieldExpression.add 6654 6671, FieldExpression.mul 3023 6619, FieldExpression.add 6654 6673, FieldExpression.mul 3026 6621, FieldExpression.add 6654 6675, FieldExpression.mul 3029 6623, FieldExpression.add 6654 6677, FieldExpression.mul 3032 6625, FieldExpression.add 6654 6679, FieldExpression.mul 3035 6627, FieldExpression.add 6654 6681, FieldExpression.mul 3038 6629, FieldExpression.add 6654 6683, FieldExpression.mul 3041 6631, FieldExpression.add 6654 6685, FieldExpression.add 3716 6656] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_209 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6688
      ([FieldExpression.sub 682 6687, FieldExpression.sub 682 3716, FieldExpression.add 3716 6689, FieldExpression.mul 6690 6690, FieldExpression.mul 6691 6691, FieldExpression.mul 6691 6692, FieldExpression.mul 6690 6693, FieldExpression.add 6658 6694, FieldExpression.add 6660 6695, FieldExpression.add 6662 6696, FieldExpression.add 6664 6697, FieldExpression.add 6666 6698, FieldExpression.add 6668 6699, FieldExpression.add 6670 6700, FieldExpression.add 6672 6701, FieldExpression.add 6674 6702, FieldExpression.add 6676 6703, FieldExpression.add 6678 6704, FieldExpression.add 6680 6705, FieldExpression.add 6682 6706, FieldExpression.add 6684 6707, FieldExpression.add 6686 6708, FieldExpression.mul 2996 6694, FieldExpression.add 6709 6710, FieldExpression.mul 2999 6658, FieldExpression.add 6709 6712, FieldExpression.mul 3002 6660, FieldExpression.add 6709 6714, FieldExpression.mul 3005 6662, FieldExpression.add 6709 6716, FieldExpression.mul 3008 6664, FieldExpression.add 6709 6718] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_210 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6720
      ([FieldExpression.mul 3011 6666, FieldExpression.add 6709 6720, FieldExpression.mul 3014 6668, FieldExpression.add 6709 6722, FieldExpression.mul 3017 6670, FieldExpression.add 6709 6724, FieldExpression.mul 3020 6672, FieldExpression.add 6709 6726, FieldExpression.mul 3023 6674, FieldExpression.add 6709 6728, FieldExpression.mul 3026 6676, FieldExpression.add 6709 6730, FieldExpression.mul 3029 6678, FieldExpression.add 6709 6732, FieldExpression.mul 3032 6680, FieldExpression.add 6709 6734, FieldExpression.mul 3035 6682, FieldExpression.add 6709 6736, FieldExpression.mul 3038 6684, FieldExpression.add 6709 6738, FieldExpression.mul 3041 6686, FieldExpression.add 6709 6740, FieldExpression.add 3772 6711, FieldExpression.sub 683 6742, FieldExpression.sub 683 3772, FieldExpression.add 3772 6744, FieldExpression.mul 6745 6745, FieldExpression.mul 6746 6746, FieldExpression.mul 6746 6747, FieldExpression.mul 6745 6748, FieldExpression.add 6713 6749, FieldExpression.add 6715 6750] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_211 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6752
      ([FieldExpression.add 6717 6751, FieldExpression.add 6719 6752, FieldExpression.add 6721 6753, FieldExpression.add 6723 6754, FieldExpression.add 6725 6755, FieldExpression.add 6727 6756, FieldExpression.add 6729 6757, FieldExpression.add 6731 6758, FieldExpression.add 6733 6759, FieldExpression.add 6735 6760, FieldExpression.add 6737 6761, FieldExpression.add 6739 6762, FieldExpression.add 6741 6763, FieldExpression.mul 2996 6749, FieldExpression.add 6764 6765, FieldExpression.mul 2999 6713, FieldExpression.add 6764 6767, FieldExpression.mul 3002 6715, FieldExpression.add 6764 6769, FieldExpression.mul 3005 6717, FieldExpression.add 6764 6771, FieldExpression.mul 3008 6719, FieldExpression.add 6764 6773, FieldExpression.mul 3011 6721, FieldExpression.add 6764 6775, FieldExpression.mul 3014 6723, FieldExpression.add 6764 6777, FieldExpression.mul 3017 6725, FieldExpression.add 6764 6779, FieldExpression.mul 3020 6727, FieldExpression.add 6764 6781, FieldExpression.mul 3023 6729] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_212 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6784
      ([FieldExpression.add 6764 6783, FieldExpression.mul 3026 6731, FieldExpression.add 6764 6785, FieldExpression.mul 3029 6733, FieldExpression.add 6764 6787, FieldExpression.mul 3032 6735, FieldExpression.add 6764 6789, FieldExpression.mul 3035 6737, FieldExpression.add 6764 6791, FieldExpression.mul 3038 6739, FieldExpression.add 6764 6793, FieldExpression.mul 3041 6741, FieldExpression.add 6764 6795, FieldExpression.add 3828 6766, FieldExpression.sub 684 6797, FieldExpression.sub 684 3828, FieldExpression.add 3828 6799, FieldExpression.mul 6800 6800, FieldExpression.mul 6801 6801, FieldExpression.mul 6801 6802, FieldExpression.mul 6800 6803, FieldExpression.add 6768 6804, FieldExpression.add 6770 6805, FieldExpression.add 6772 6806, FieldExpression.add 6774 6807, FieldExpression.add 6776 6808, FieldExpression.add 6778 6809, FieldExpression.add 6780 6810, FieldExpression.add 6782 6811, FieldExpression.add 6784 6812, FieldExpression.add 6786 6813, FieldExpression.add 6788 6814] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_213 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6816
      ([FieldExpression.add 6790 6815, FieldExpression.add 6792 6816, FieldExpression.add 6794 6817, FieldExpression.add 6796 6818, FieldExpression.mul 2996 6804, FieldExpression.add 6819 6820, FieldExpression.mul 2999 6768, FieldExpression.add 6819 6822, FieldExpression.mul 3002 6770, FieldExpression.add 6819 6824, FieldExpression.mul 3005 6772, FieldExpression.add 6819 6826, FieldExpression.mul 3008 6774, FieldExpression.add 6819 6828, FieldExpression.mul 3011 6776, FieldExpression.add 6819 6830, FieldExpression.mul 3014 6778, FieldExpression.add 6819 6832, FieldExpression.mul 3017 6780, FieldExpression.add 6819 6834, FieldExpression.mul 3020 6782, FieldExpression.add 6819 6836, FieldExpression.mul 3023 6784, FieldExpression.add 6819 6838, FieldExpression.mul 3026 6786, FieldExpression.add 6819 6840, FieldExpression.mul 3029 6788, FieldExpression.add 6819 6842, FieldExpression.mul 3032 6790, FieldExpression.add 6819 6844, FieldExpression.mul 3035 6792, FieldExpression.add 6819 6846] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_214 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6848
      ([FieldExpression.mul 3038 6794, FieldExpression.add 6819 6848, FieldExpression.mul 3041 6796, FieldExpression.add 6819 6850, FieldExpression.add 3884 6821, FieldExpression.sub 685 6852, FieldExpression.sub 685 3884, FieldExpression.add 3884 6854, FieldExpression.mul 6855 6855, FieldExpression.mul 6856 6856, FieldExpression.mul 6856 6857, FieldExpression.mul 6855 6858, FieldExpression.add 6823 6859, FieldExpression.add 6825 6860, FieldExpression.add 6827 6861, FieldExpression.add 6829 6862, FieldExpression.add 6831 6863, FieldExpression.add 6833 6864, FieldExpression.add 6835 6865, FieldExpression.add 6837 6866, FieldExpression.add 6839 6867, FieldExpression.add 6841 6868, FieldExpression.add 6843 6869, FieldExpression.add 6845 6870, FieldExpression.add 6847 6871, FieldExpression.add 6849 6872, FieldExpression.add 6851 6873, FieldExpression.mul 2996 6859, FieldExpression.add 6874 6875, FieldExpression.mul 2999 6823, FieldExpression.add 6874 6877, FieldExpression.mul 3002 6825] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_215 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6880
      ([FieldExpression.add 6874 6879, FieldExpression.mul 3005 6827, FieldExpression.add 6874 6881, FieldExpression.mul 3008 6829, FieldExpression.add 6874 6883, FieldExpression.mul 3011 6831, FieldExpression.add 6874 6885, FieldExpression.mul 3014 6833, FieldExpression.add 6874 6887, FieldExpression.mul 3017 6835, FieldExpression.add 6874 6889, FieldExpression.mul 3020 6837, FieldExpression.add 6874 6891, FieldExpression.mul 3023 6839, FieldExpression.add 6874 6893, FieldExpression.mul 3026 6841, FieldExpression.add 6874 6895, FieldExpression.mul 3029 6843, FieldExpression.add 6874 6897, FieldExpression.mul 3032 6845, FieldExpression.add 6874 6899, FieldExpression.mul 3035 6847, FieldExpression.add 6874 6901, FieldExpression.mul 3038 6849, FieldExpression.add 6874 6903, FieldExpression.mul 3041 6851, FieldExpression.add 6874 6905, FieldExpression.add 3940 6876, FieldExpression.sub 686 6907, FieldExpression.sub 686 3940, FieldExpression.add 3940 6909, FieldExpression.mul 6910 6910] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_216 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6912
      ([FieldExpression.mul 6911 6911, FieldExpression.mul 6911 6912, FieldExpression.mul 6910 6913, FieldExpression.add 6878 6914, FieldExpression.add 6880 6915, FieldExpression.add 6882 6916, FieldExpression.add 6884 6917, FieldExpression.add 6886 6918, FieldExpression.add 6888 6919, FieldExpression.add 6890 6920, FieldExpression.add 6892 6921, FieldExpression.add 6894 6922, FieldExpression.add 6896 6923, FieldExpression.add 6898 6924, FieldExpression.add 6900 6925, FieldExpression.add 6902 6926, FieldExpression.add 6904 6927, FieldExpression.add 6906 6928, FieldExpression.mul 2996 6914, FieldExpression.add 6929 6930, FieldExpression.mul 2999 6878, FieldExpression.add 6929 6932, FieldExpression.mul 3002 6880, FieldExpression.add 6929 6934, FieldExpression.mul 3005 6882, FieldExpression.add 6929 6936, FieldExpression.mul 3008 6884, FieldExpression.add 6929 6938, FieldExpression.mul 3011 6886, FieldExpression.add 6929 6940, FieldExpression.mul 3014 6888, FieldExpression.add 6929 6942] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_217 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6944
      ([FieldExpression.mul 3017 6890, FieldExpression.add 6929 6944, FieldExpression.mul 3020 6892, FieldExpression.add 6929 6946, FieldExpression.mul 3023 6894, FieldExpression.add 6929 6948, FieldExpression.mul 3026 6896, FieldExpression.add 6929 6950, FieldExpression.mul 3029 6898, FieldExpression.add 6929 6952, FieldExpression.mul 3032 6900, FieldExpression.add 6929 6954, FieldExpression.mul 3035 6902, FieldExpression.add 6929 6956, FieldExpression.mul 3038 6904, FieldExpression.add 6929 6958, FieldExpression.mul 3041 6906, FieldExpression.add 6929 6960, FieldExpression.add 3996 6931, FieldExpression.sub 687 6962, FieldExpression.sub 687 3996, FieldExpression.add 3996 6964, FieldExpression.mul 6965 6965, FieldExpression.mul 6966 6966, FieldExpression.mul 6966 6967, FieldExpression.mul 6965 6968, FieldExpression.add 6933 6969, FieldExpression.add 6935 6970, FieldExpression.add 6937 6971, FieldExpression.add 6939 6972, FieldExpression.add 6941 6973, FieldExpression.add 6943 6974] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_218 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 6976
      ([FieldExpression.add 6945 6975, FieldExpression.add 6947 6976, FieldExpression.add 6949 6977, FieldExpression.add 6951 6978, FieldExpression.add 6953 6979, FieldExpression.add 6955 6980, FieldExpression.add 6957 6981, FieldExpression.add 6959 6982, FieldExpression.add 6961 6983, FieldExpression.mul 2996 6969, FieldExpression.add 6984 6985, FieldExpression.mul 2999 6933, FieldExpression.add 6984 6987, FieldExpression.mul 3002 6935, FieldExpression.add 6984 6989, FieldExpression.mul 3005 6937, FieldExpression.add 6984 6991, FieldExpression.mul 3008 6939, FieldExpression.add 6984 6993, FieldExpression.mul 3011 6941, FieldExpression.add 6984 6995, FieldExpression.mul 3014 6943, FieldExpression.add 6984 6997, FieldExpression.mul 3017 6945, FieldExpression.add 6984 6999, FieldExpression.mul 3020 6947, FieldExpression.add 6984 7001, FieldExpression.mul 3023 6949, FieldExpression.add 6984 7003, FieldExpression.mul 3026 6951, FieldExpression.add 6984 7005, FieldExpression.mul 3029 6953] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_219 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7008
      ([FieldExpression.add 6984 7007, FieldExpression.mul 3032 6955, FieldExpression.add 6984 7009, FieldExpression.mul 3035 6957, FieldExpression.add 6984 7011, FieldExpression.mul 3038 6959, FieldExpression.add 6984 7013, FieldExpression.mul 3041 6961, FieldExpression.add 6984 7015, FieldExpression.add 4052 6986, FieldExpression.sub 688 7017, FieldExpression.sub 688 4052, FieldExpression.add 4052 7019, FieldExpression.mul 7020 7020, FieldExpression.mul 7021 7021, FieldExpression.mul 7021 7022, FieldExpression.mul 7020 7023, FieldExpression.add 6988 7024, FieldExpression.add 6990 7025, FieldExpression.add 6992 7026, FieldExpression.add 6994 7027, FieldExpression.add 6996 7028, FieldExpression.add 6998 7029, FieldExpression.add 7000 7030, FieldExpression.add 7002 7031, FieldExpression.add 7004 7032, FieldExpression.add 7006 7033, FieldExpression.add 7008 7034, FieldExpression.add 7010 7035, FieldExpression.add 7012 7036, FieldExpression.add 7014 7037, FieldExpression.add 7016 7038] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_220 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7040
      ([FieldExpression.mul 2996 7024, FieldExpression.add 7039 7040, FieldExpression.mul 2999 6988, FieldExpression.add 7039 7042, FieldExpression.mul 3002 6990, FieldExpression.add 7039 7044, FieldExpression.mul 3005 6992, FieldExpression.add 7039 7046, FieldExpression.mul 3008 6994, FieldExpression.add 7039 7048, FieldExpression.mul 3011 6996, FieldExpression.add 7039 7050, FieldExpression.mul 3014 6998, FieldExpression.add 7039 7052, FieldExpression.mul 3017 7000, FieldExpression.add 7039 7054, FieldExpression.mul 3020 7002, FieldExpression.add 7039 7056, FieldExpression.mul 3023 7004, FieldExpression.add 7039 7058, FieldExpression.mul 3026 7006, FieldExpression.add 7039 7060, FieldExpression.mul 3029 7008, FieldExpression.add 7039 7062, FieldExpression.mul 3032 7010, FieldExpression.add 7039 7064, FieldExpression.mul 3035 7012, FieldExpression.add 7039 7066, FieldExpression.mul 3038 7014, FieldExpression.add 7039 7068, FieldExpression.mul 3041 7016, FieldExpression.add 7039 7070] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_221 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7072
      ([FieldExpression.add 4108 7041, FieldExpression.sub 689 7072, FieldExpression.sub 689 4108, FieldExpression.add 4108 7074, FieldExpression.mul 7075 7075, FieldExpression.mul 7076 7076, FieldExpression.mul 7076 7077, FieldExpression.mul 7075 7078, FieldExpression.add 7043 7079, FieldExpression.add 7045 7080, FieldExpression.add 7047 7081, FieldExpression.add 7049 7082, FieldExpression.add 7051 7083, FieldExpression.add 7053 7084, FieldExpression.add 7055 7085, FieldExpression.add 7057 7086, FieldExpression.add 7059 7087, FieldExpression.add 7061 7088, FieldExpression.add 7063 7089, FieldExpression.add 7065 7090, FieldExpression.add 7067 7091, FieldExpression.add 7069 7092, FieldExpression.add 7071 7093, FieldExpression.mul 2996 7079, FieldExpression.add 7094 7095, FieldExpression.mul 2999 7043, FieldExpression.add 7094 7097, FieldExpression.mul 3002 7045, FieldExpression.add 7094 7099, FieldExpression.mul 3005 7047, FieldExpression.add 7094 7101, FieldExpression.mul 3008 7049] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_222 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7104
      ([FieldExpression.add 7094 7103, FieldExpression.mul 3011 7051, FieldExpression.add 7094 7105, FieldExpression.mul 3014 7053, FieldExpression.add 7094 7107, FieldExpression.mul 3017 7055, FieldExpression.add 7094 7109, FieldExpression.mul 3020 7057, FieldExpression.add 7094 7111, FieldExpression.mul 3023 7059, FieldExpression.add 7094 7113, FieldExpression.mul 3026 7061, FieldExpression.add 7094 7115, FieldExpression.mul 3029 7063, FieldExpression.add 7094 7117, FieldExpression.mul 3032 7065, FieldExpression.add 7094 7119, FieldExpression.mul 3035 7067, FieldExpression.add 7094 7121, FieldExpression.mul 3038 7069, FieldExpression.add 7094 7123, FieldExpression.mul 3041 7071, FieldExpression.add 7094 7125, FieldExpression.add 4164 7096, FieldExpression.sub 690 7127, FieldExpression.sub 690 4164, FieldExpression.add 4164 7129, FieldExpression.mul 7130 7130, FieldExpression.mul 7131 7131, FieldExpression.mul 7131 7132, FieldExpression.mul 7130 7133, FieldExpression.add 7098 7134] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_223 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7136
      ([FieldExpression.add 7100 7135, FieldExpression.add 7102 7136, FieldExpression.add 7104 7137, FieldExpression.add 7106 7138, FieldExpression.add 7108 7139, FieldExpression.add 7110 7140, FieldExpression.add 7112 7141, FieldExpression.add 7114 7142, FieldExpression.add 7116 7143, FieldExpression.add 7118 7144, FieldExpression.add 7120 7145, FieldExpression.add 7122 7146, FieldExpression.add 7124 7147, FieldExpression.add 7126 7148, FieldExpression.mul 2996 7134, FieldExpression.add 7149 7150, FieldExpression.mul 2999 7098, FieldExpression.add 7149 7152, FieldExpression.mul 3002 7100, FieldExpression.add 7149 7154, FieldExpression.mul 3005 7102, FieldExpression.add 7149 7156, FieldExpression.mul 3008 7104, FieldExpression.add 7149 7158, FieldExpression.mul 3011 7106, FieldExpression.add 7149 7160, FieldExpression.mul 3014 7108, FieldExpression.add 7149 7162, FieldExpression.mul 3017 7110, FieldExpression.add 7149 7164, FieldExpression.mul 3020 7112, FieldExpression.add 7149 7166] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_224 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7168
      ([FieldExpression.mul 3023 7114, FieldExpression.add 7149 7168, FieldExpression.mul 3026 7116, FieldExpression.add 7149 7170, FieldExpression.mul 3029 7118, FieldExpression.add 7149 7172, FieldExpression.mul 3032 7120, FieldExpression.add 7149 7174, FieldExpression.mul 3035 7122, FieldExpression.add 7149 7176, FieldExpression.mul 3038 7124, FieldExpression.add 7149 7178, FieldExpression.mul 3041 7126, FieldExpression.add 7149 7180, FieldExpression.add 4220 7151, FieldExpression.sub 691 7182, FieldExpression.sub 691 4220, FieldExpression.add 4224 7153, FieldExpression.sub 692 7185, FieldExpression.sub 692 4224, FieldExpression.add 4228 7155, FieldExpression.sub 693 7188, FieldExpression.sub 693 4228, FieldExpression.add 4232 7157, FieldExpression.sub 694 7191, FieldExpression.sub 694 4232, FieldExpression.add 4236 7159, FieldExpression.sub 695 7194, FieldExpression.sub 695 4236, FieldExpression.add 4240 7161, FieldExpression.sub 696 7197, FieldExpression.sub 696 4240] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_225 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7200
      ([FieldExpression.add 4244 7163, FieldExpression.sub 697 7200, FieldExpression.sub 697 4244, FieldExpression.add 4248 7165, FieldExpression.sub 698 7203, FieldExpression.sub 698 4248, FieldExpression.add 4252 7167, FieldExpression.sub 699 7206, FieldExpression.sub 699 4252, FieldExpression.add 4256 7169, FieldExpression.sub 700 7209, FieldExpression.sub 700 4256, FieldExpression.add 4260 7171, FieldExpression.sub 701 7212, FieldExpression.sub 701 4260, FieldExpression.add 4264 7173, FieldExpression.sub 702 7215, FieldExpression.sub 702 4264, FieldExpression.add 4268 7175, FieldExpression.sub 703 7218, FieldExpression.sub 703 4268, FieldExpression.add 4272 7177, FieldExpression.sub 704 7221, FieldExpression.sub 704 4272, FieldExpression.add 4276 7179, FieldExpression.sub 705 7224, FieldExpression.sub 705 4276, FieldExpression.add 4280 7181, FieldExpression.sub 706 7227, FieldExpression.sub 706 4280, FieldExpression.add 4220 7184, FieldExpression.mul 7230 7230] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_226 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7232
      ([FieldExpression.mul 7231 7231, FieldExpression.mul 7231 7232, FieldExpression.mul 7230 7233, FieldExpression.add 4224 7187, FieldExpression.mul 7235 7235, FieldExpression.mul 7236 7236, FieldExpression.mul 7236 7237, FieldExpression.mul 7235 7238, FieldExpression.add 4228 7190, FieldExpression.mul 7240 7240, FieldExpression.mul 7241 7241, FieldExpression.mul 7241 7242, FieldExpression.mul 7240 7243, FieldExpression.add 4232 7193, FieldExpression.mul 7245 7245, FieldExpression.mul 7246 7246, FieldExpression.mul 7246 7247, FieldExpression.mul 7245 7248, FieldExpression.add 4236 7196, FieldExpression.mul 7250 7250, FieldExpression.mul 7251 7251, FieldExpression.mul 7251 7252, FieldExpression.mul 7250 7253, FieldExpression.add 4240 7199, FieldExpression.mul 7255 7255, FieldExpression.mul 7256 7256, FieldExpression.mul 7256 7257, FieldExpression.mul 7255 7258, FieldExpression.add 4244 7202, FieldExpression.mul 7260 7260, FieldExpression.mul 7261 7261, FieldExpression.mul 7261 7262] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_227 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7264
      ([FieldExpression.mul 7260 7263, FieldExpression.add 4248 7205, FieldExpression.mul 7265 7265, FieldExpression.mul 7266 7266, FieldExpression.mul 7266 7267, FieldExpression.mul 7265 7268, FieldExpression.add 4252 7208, FieldExpression.mul 7270 7270, FieldExpression.mul 7271 7271, FieldExpression.mul 7271 7272, FieldExpression.mul 7270 7273, FieldExpression.add 4256 7211, FieldExpression.mul 7275 7275, FieldExpression.mul 7276 7276, FieldExpression.mul 7276 7277, FieldExpression.mul 7275 7278, FieldExpression.add 4260 7214, FieldExpression.mul 7280 7280, FieldExpression.mul 7281 7281, FieldExpression.mul 7281 7282, FieldExpression.mul 7280 7283, FieldExpression.add 4264 7217, FieldExpression.mul 7285 7285, FieldExpression.mul 7286 7286, FieldExpression.mul 7286 7287, FieldExpression.mul 7285 7288, FieldExpression.add 4268 7220, FieldExpression.mul 7290 7290, FieldExpression.mul 7291 7291, FieldExpression.mul 7291 7292, FieldExpression.mul 7290 7293, FieldExpression.add 4272 7223] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_228 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7296
      ([FieldExpression.mul 7295 7295, FieldExpression.mul 7296 7296, FieldExpression.mul 7296 7297, FieldExpression.mul 7295 7298, FieldExpression.add 4276 7226, FieldExpression.mul 7300 7300, FieldExpression.mul 7301 7301, FieldExpression.mul 7301 7302, FieldExpression.mul 7300 7303, FieldExpression.add 4280 7229, FieldExpression.mul 7305 7305, FieldExpression.mul 7306 7306, FieldExpression.mul 7306 7307, FieldExpression.mul 7305 7308, FieldExpression.add 7234 7239, FieldExpression.add 7244 7310, FieldExpression.add 7249 7311, FieldExpression.add 7234 7312, FieldExpression.add 7239 7312, FieldExpression.add 7244 7312, FieldExpression.add 7249 7312, FieldExpression.add 7254 7259, FieldExpression.add 7264 7317, FieldExpression.add 7269 7318, FieldExpression.add 7254 7319, FieldExpression.add 7259 7319, FieldExpression.add 7264 7319, FieldExpression.add 7269 7319, FieldExpression.add 7274 7279, FieldExpression.add 7284 7324, FieldExpression.add 7289 7325, FieldExpression.add 7274 7326] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_229 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7328
      ([FieldExpression.add 7279 7326, FieldExpression.add 7284 7326, FieldExpression.add 7289 7326, FieldExpression.add 7294 7299, FieldExpression.add 7304 7331, FieldExpression.add 7309 7332, FieldExpression.add 7294 7333, FieldExpression.add 7299 7333, FieldExpression.add 7304 7333, FieldExpression.add 7309 7333, FieldExpression.add 7313 7320, FieldExpression.add 7327 7334, FieldExpression.add 7338 7339, FieldExpression.add 7320 7340, FieldExpression.add 7334 7340, FieldExpression.add 7313 7313, FieldExpression.add 7342 7343, FieldExpression.add 7327 7327, FieldExpression.add 7341 7345, FieldExpression.add 7338 7341, FieldExpression.add 7339 7342, FieldExpression.add 7314 7321, FieldExpression.add 7328 7335, FieldExpression.add 7349 7350, FieldExpression.add 7321 7351, FieldExpression.add 7335 7351, FieldExpression.add 7314 7314, FieldExpression.add 7353 7354, FieldExpression.add 7328 7328, FieldExpression.add 7352 7356, FieldExpression.add 7349 7352, FieldExpression.add 7350 7353] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_230 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7360
      ([FieldExpression.add 7315 7322, FieldExpression.add 7329 7336, FieldExpression.add 7360 7361, FieldExpression.add 7322 7362, FieldExpression.add 7336 7362, FieldExpression.add 7315 7315, FieldExpression.add 7364 7365, FieldExpression.add 7329 7329, FieldExpression.add 7363 7367, FieldExpression.add 7360 7363, FieldExpression.add 7361 7364, FieldExpression.add 7316 7323, FieldExpression.add 7330 7337, FieldExpression.add 7371 7372, FieldExpression.add 7323 7373, FieldExpression.add 7337 7373, FieldExpression.add 7316 7316, FieldExpression.add 7375 7376, FieldExpression.add 7330 7330, FieldExpression.add 7374 7378, FieldExpression.add 7371 7374, FieldExpression.add 7372 7375, FieldExpression.add 4436 7347, FieldExpression.sub 707 7382, FieldExpression.sub 707 4436, FieldExpression.add 4440 7358, FieldExpression.sub 708 7385, FieldExpression.sub 708 4440, FieldExpression.add 4444 7369, FieldExpression.sub 709 7388, FieldExpression.sub 709 4444, FieldExpression.add 4448 7380] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_231 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7392
      ([FieldExpression.sub 710 7391, FieldExpression.sub 710 4448, FieldExpression.add 4452 7346, FieldExpression.sub 711 7394, FieldExpression.sub 711 4452, FieldExpression.add 4456 7357, FieldExpression.sub 712 7397, FieldExpression.sub 712 4456, FieldExpression.add 4460 7368, FieldExpression.sub 713 7400, FieldExpression.sub 713 4460, FieldExpression.add 4464 7379, FieldExpression.sub 714 7403, FieldExpression.sub 714 4464, FieldExpression.add 4468 7348, FieldExpression.sub 715 7406, FieldExpression.sub 715 4468, FieldExpression.add 4472 7359, FieldExpression.sub 716 7409, FieldExpression.sub 716 4472, FieldExpression.add 4476 7370, FieldExpression.sub 717 7412, FieldExpression.sub 717 4476, FieldExpression.add 4480 7381, FieldExpression.sub 718 7415, FieldExpression.sub 718 4480, FieldExpression.add 4484 7344, FieldExpression.sub 719 7418, FieldExpression.sub 719 4484, FieldExpression.add 4488 7355, FieldExpression.sub 720 7421, FieldExpression.sub 720 4488] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_232 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7424
      ([FieldExpression.add 4492 7366, FieldExpression.sub 721 7424, FieldExpression.sub 721 4492, FieldExpression.add 4496 7377, FieldExpression.sub 722 7427, FieldExpression.sub 722 4496, FieldExpression.add 4436 7384, FieldExpression.mul 7430 7430, FieldExpression.mul 7431 7431, FieldExpression.mul 7431 7432, FieldExpression.mul 7430 7433, FieldExpression.add 4440 7387, FieldExpression.mul 7435 7435, FieldExpression.mul 7436 7436, FieldExpression.mul 7436 7437, FieldExpression.mul 7435 7438, FieldExpression.add 4444 7390, FieldExpression.mul 7440 7440, FieldExpression.mul 7441 7441, FieldExpression.mul 7441 7442, FieldExpression.mul 7440 7443, FieldExpression.add 4448 7393, FieldExpression.mul 7445 7445, FieldExpression.mul 7446 7446, FieldExpression.mul 7446 7447, FieldExpression.mul 7445 7448, FieldExpression.add 4452 7396, FieldExpression.mul 7450 7450, FieldExpression.mul 7451 7451, FieldExpression.mul 7451 7452, FieldExpression.mul 7450 7453, FieldExpression.add 4456 7399] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_233 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7456
      ([FieldExpression.mul 7455 7455, FieldExpression.mul 7456 7456, FieldExpression.mul 7456 7457, FieldExpression.mul 7455 7458, FieldExpression.add 4460 7402, FieldExpression.mul 7460 7460, FieldExpression.mul 7461 7461, FieldExpression.mul 7461 7462, FieldExpression.mul 7460 7463, FieldExpression.add 4464 7405, FieldExpression.mul 7465 7465, FieldExpression.mul 7466 7466, FieldExpression.mul 7466 7467, FieldExpression.mul 7465 7468, FieldExpression.add 4468 7408, FieldExpression.mul 7470 7470, FieldExpression.mul 7471 7471, FieldExpression.mul 7471 7472, FieldExpression.mul 7470 7473, FieldExpression.add 4472 7411, FieldExpression.mul 7475 7475, FieldExpression.mul 7476 7476, FieldExpression.mul 7476 7477, FieldExpression.mul 7475 7478, FieldExpression.add 4476 7414, FieldExpression.mul 7480 7480, FieldExpression.mul 7481 7481, FieldExpression.mul 7481 7482, FieldExpression.mul 7480 7483, FieldExpression.add 4480 7417, FieldExpression.mul 7485 7485, FieldExpression.mul 7486 7486] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_234 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7488
      ([FieldExpression.mul 7486 7487, FieldExpression.mul 7485 7488, FieldExpression.add 4484 7420, FieldExpression.mul 7490 7490, FieldExpression.mul 7491 7491, FieldExpression.mul 7491 7492, FieldExpression.mul 7490 7493, FieldExpression.add 4488 7423, FieldExpression.mul 7495 7495, FieldExpression.mul 7496 7496, FieldExpression.mul 7496 7497, FieldExpression.mul 7495 7498, FieldExpression.add 4492 7426, FieldExpression.mul 7500 7500, FieldExpression.mul 7501 7501, FieldExpression.mul 7501 7502, FieldExpression.mul 7500 7503, FieldExpression.add 4496 7429, FieldExpression.mul 7505 7505, FieldExpression.mul 7506 7506, FieldExpression.mul 7506 7507, FieldExpression.mul 7505 7508, FieldExpression.add 7434 7439, FieldExpression.add 7444 7510, FieldExpression.add 7449 7511, FieldExpression.add 7434 7512, FieldExpression.add 7439 7512, FieldExpression.add 7444 7512, FieldExpression.add 7449 7512, FieldExpression.add 7454 7459, FieldExpression.add 7464 7517, FieldExpression.add 7469 7518] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_235 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7520
      ([FieldExpression.add 7454 7519, FieldExpression.add 7459 7519, FieldExpression.add 7464 7519, FieldExpression.add 7469 7519, FieldExpression.add 7474 7479, FieldExpression.add 7484 7524, FieldExpression.add 7489 7525, FieldExpression.add 7474 7526, FieldExpression.add 7479 7526, FieldExpression.add 7484 7526, FieldExpression.add 7489 7526, FieldExpression.add 7494 7499, FieldExpression.add 7504 7531, FieldExpression.add 7509 7532, FieldExpression.add 7494 7533, FieldExpression.add 7499 7533, FieldExpression.add 7504 7533, FieldExpression.add 7509 7533, FieldExpression.add 7513 7520, FieldExpression.add 7527 7534, FieldExpression.add 7538 7539, FieldExpression.add 7520 7540, FieldExpression.add 7534 7540, FieldExpression.add 7513 7513, FieldExpression.add 7542 7543, FieldExpression.add 7527 7527, FieldExpression.add 7541 7545, FieldExpression.add 7538 7541, FieldExpression.add 7539 7542, FieldExpression.add 7514 7521, FieldExpression.add 7528 7535, FieldExpression.add 7549 7550] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_236 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7552
      ([FieldExpression.add 7521 7551, FieldExpression.add 7535 7551, FieldExpression.add 7514 7514, FieldExpression.add 7553 7554, FieldExpression.add 7528 7528, FieldExpression.add 7552 7556, FieldExpression.add 7549 7552, FieldExpression.add 7550 7553, FieldExpression.add 7515 7522, FieldExpression.add 7529 7536, FieldExpression.add 7560 7561, FieldExpression.add 7522 7562, FieldExpression.add 7536 7562, FieldExpression.add 7515 7515, FieldExpression.add 7564 7565, FieldExpression.add 7529 7529, FieldExpression.add 7563 7567, FieldExpression.add 7560 7563, FieldExpression.add 7561 7564, FieldExpression.add 7516 7523, FieldExpression.add 7530 7537, FieldExpression.add 7571 7572, FieldExpression.add 7523 7573, FieldExpression.add 7537 7573, FieldExpression.add 7516 7516, FieldExpression.add 7575 7576, FieldExpression.add 7530 7530, FieldExpression.add 7574 7578, FieldExpression.add 7571 7574, FieldExpression.add 7572 7575, FieldExpression.add 4652 7547, FieldExpression.sub 723 7582] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_237 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7584
      ([FieldExpression.sub 723 4652, FieldExpression.add 4656 7558, FieldExpression.sub 724 7585, FieldExpression.sub 724 4656, FieldExpression.add 4660 7569, FieldExpression.sub 725 7588, FieldExpression.sub 725 4660, FieldExpression.add 4664 7580, FieldExpression.sub 726 7591, FieldExpression.sub 726 4664, FieldExpression.add 4668 7546, FieldExpression.sub 727 7594, FieldExpression.sub 727 4668, FieldExpression.add 4672 7557, FieldExpression.sub 728 7597, FieldExpression.sub 728 4672, FieldExpression.add 4676 7568, FieldExpression.sub 729 7600, FieldExpression.sub 729 4676, FieldExpression.add 4680 7579, FieldExpression.sub 730 7603, FieldExpression.sub 730 4680, FieldExpression.add 4684 7548, FieldExpression.sub 731 7606, FieldExpression.sub 731 4684, FieldExpression.add 4688 7559, FieldExpression.sub 732 7609, FieldExpression.sub 732 4688, FieldExpression.add 4692 7570, FieldExpression.sub 733 7612, FieldExpression.sub 733 4692, FieldExpression.add 4696 7581] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_238 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7616
      ([FieldExpression.sub 734 7615, FieldExpression.sub 734 4696, FieldExpression.add 4700 7544, FieldExpression.sub 735 7618, FieldExpression.sub 735 4700, FieldExpression.add 4704 7555, FieldExpression.sub 736 7621, FieldExpression.sub 736 4704, FieldExpression.add 4708 7566, FieldExpression.sub 737 7624, FieldExpression.sub 737 4708, FieldExpression.add 4712 7577, FieldExpression.sub 738 7627, FieldExpression.sub 738 4712, FieldExpression.add 4652 7584, FieldExpression.mul 7630 7630, FieldExpression.mul 7631 7631, FieldExpression.mul 7631 7632, FieldExpression.mul 7630 7633, FieldExpression.add 4656 7587, FieldExpression.mul 7635 7635, FieldExpression.mul 7636 7636, FieldExpression.mul 7636 7637, FieldExpression.mul 7635 7638, FieldExpression.add 4660 7590, FieldExpression.mul 7640 7640, FieldExpression.mul 7641 7641, FieldExpression.mul 7641 7642, FieldExpression.mul 7640 7643, FieldExpression.add 4664 7593, FieldExpression.mul 7645 7645, FieldExpression.mul 7646 7646] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_239 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7648
      ([FieldExpression.mul 7646 7647, FieldExpression.mul 7645 7648, FieldExpression.add 4668 7596, FieldExpression.mul 7650 7650, FieldExpression.mul 7651 7651, FieldExpression.mul 7651 7652, FieldExpression.mul 7650 7653, FieldExpression.add 4672 7599, FieldExpression.mul 7655 7655, FieldExpression.mul 7656 7656, FieldExpression.mul 7656 7657, FieldExpression.mul 7655 7658, FieldExpression.add 4676 7602, FieldExpression.mul 7660 7660, FieldExpression.mul 7661 7661, FieldExpression.mul 7661 7662, FieldExpression.mul 7660 7663, FieldExpression.add 4680 7605, FieldExpression.mul 7665 7665, FieldExpression.mul 7666 7666, FieldExpression.mul 7666 7667, FieldExpression.mul 7665 7668, FieldExpression.add 4684 7608, FieldExpression.mul 7670 7670, FieldExpression.mul 7671 7671, FieldExpression.mul 7671 7672, FieldExpression.mul 7670 7673, FieldExpression.add 4688 7611, FieldExpression.mul 7675 7675, FieldExpression.mul 7676 7676, FieldExpression.mul 7676 7677, FieldExpression.mul 7675 7678] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_240 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7680
      ([FieldExpression.add 4692 7614, FieldExpression.mul 7680 7680, FieldExpression.mul 7681 7681, FieldExpression.mul 7681 7682, FieldExpression.mul 7680 7683, FieldExpression.add 4696 7617, FieldExpression.mul 7685 7685, FieldExpression.mul 7686 7686, FieldExpression.mul 7686 7687, FieldExpression.mul 7685 7688, FieldExpression.add 4700 7620, FieldExpression.mul 7690 7690, FieldExpression.mul 7691 7691, FieldExpression.mul 7691 7692, FieldExpression.mul 7690 7693, FieldExpression.add 4704 7623, FieldExpression.mul 7695 7695, FieldExpression.mul 7696 7696, FieldExpression.mul 7696 7697, FieldExpression.mul 7695 7698, FieldExpression.add 4708 7626, FieldExpression.mul 7700 7700, FieldExpression.mul 7701 7701, FieldExpression.mul 7701 7702, FieldExpression.mul 7700 7703, FieldExpression.add 4712 7629, FieldExpression.mul 7705 7705, FieldExpression.mul 7706 7706, FieldExpression.mul 7706 7707, FieldExpression.mul 7705 7708, FieldExpression.add 7634 7639, FieldExpression.add 7644 7710] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_241 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7712
      ([FieldExpression.add 7649 7711, FieldExpression.add 7634 7712, FieldExpression.add 7639 7712, FieldExpression.add 7644 7712, FieldExpression.add 7649 7712, FieldExpression.add 7654 7659, FieldExpression.add 7664 7717, FieldExpression.add 7669 7718, FieldExpression.add 7654 7719, FieldExpression.add 7659 7719, FieldExpression.add 7664 7719, FieldExpression.add 7669 7719, FieldExpression.add 7674 7679, FieldExpression.add 7684 7724, FieldExpression.add 7689 7725, FieldExpression.add 7674 7726, FieldExpression.add 7679 7726, FieldExpression.add 7684 7726, FieldExpression.add 7689 7726, FieldExpression.add 7694 7699, FieldExpression.add 7704 7731, FieldExpression.add 7709 7732, FieldExpression.add 7694 7733, FieldExpression.add 7699 7733, FieldExpression.add 7704 7733, FieldExpression.add 7709 7733, FieldExpression.add 7713 7720, FieldExpression.add 7727 7734, FieldExpression.add 7738 7739, FieldExpression.add 7720 7740, FieldExpression.add 7734 7740, FieldExpression.add 7713 7713] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_242 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7744
      ([FieldExpression.add 7742 7743, FieldExpression.add 7727 7727, FieldExpression.add 7741 7745, FieldExpression.add 7738 7741, FieldExpression.add 7739 7742, FieldExpression.add 7714 7721, FieldExpression.add 7728 7735, FieldExpression.add 7749 7750, FieldExpression.add 7721 7751, FieldExpression.add 7735 7751, FieldExpression.add 7714 7714, FieldExpression.add 7753 7754, FieldExpression.add 7728 7728, FieldExpression.add 7752 7756, FieldExpression.add 7749 7752, FieldExpression.add 7750 7753, FieldExpression.add 7715 7722, FieldExpression.add 7729 7736, FieldExpression.add 7760 7761, FieldExpression.add 7722 7762, FieldExpression.add 7736 7762, FieldExpression.add 7715 7715, FieldExpression.add 7764 7765, FieldExpression.add 7729 7729, FieldExpression.add 7763 7767, FieldExpression.add 7760 7763, FieldExpression.add 7761 7764, FieldExpression.add 7716 7723, FieldExpression.add 7730 7737, FieldExpression.add 7771 7772, FieldExpression.add 7723 7773, FieldExpression.add 7737 7773] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_243 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7776
      ([FieldExpression.add 7716 7716, FieldExpression.add 7775 7776, FieldExpression.add 7730 7730, FieldExpression.add 7774 7778, FieldExpression.add 7771 7774, FieldExpression.add 7772 7775, FieldExpression.add 4868 7747, FieldExpression.sub 739 7782, FieldExpression.sub 739 4868, FieldExpression.add 4872 7758, FieldExpression.sub 740 7785, FieldExpression.sub 740 4872, FieldExpression.add 4876 7769, FieldExpression.sub 741 7788, FieldExpression.sub 741 4876, FieldExpression.add 4880 7780, FieldExpression.sub 742 7791, FieldExpression.sub 742 4880, FieldExpression.add 4884 7746, FieldExpression.sub 743 7794, FieldExpression.sub 743 4884, FieldExpression.add 4888 7757, FieldExpression.sub 744 7797, FieldExpression.sub 744 4888, FieldExpression.add 4892 7768, FieldExpression.sub 745 7800, FieldExpression.sub 745 4892, FieldExpression.add 4896 7779, FieldExpression.sub 746 7803, FieldExpression.sub 746 4896, FieldExpression.add 4900 7748, FieldExpression.sub 747 7806] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_244 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7808
      ([FieldExpression.sub 747 4900, FieldExpression.add 4904 7759, FieldExpression.sub 748 7809, FieldExpression.sub 748 4904, FieldExpression.add 4908 7770, FieldExpression.sub 749 7812, FieldExpression.sub 749 4908, FieldExpression.add 4912 7781, FieldExpression.sub 750 7815, FieldExpression.sub 750 4912, FieldExpression.add 4916 7744, FieldExpression.sub 751 7818, FieldExpression.sub 751 4916, FieldExpression.add 4920 7755, FieldExpression.sub 752 7821, FieldExpression.sub 752 4920, FieldExpression.add 4924 7766, FieldExpression.sub 753 7824, FieldExpression.sub 753 4924, FieldExpression.add 4928 7777, FieldExpression.sub 754 7827, FieldExpression.sub 754 4928, FieldExpression.add 4868 7784, FieldExpression.mul 7830 7830, FieldExpression.mul 7831 7831, FieldExpression.mul 7831 7832, FieldExpression.mul 7830 7833, FieldExpression.add 4872 7787, FieldExpression.mul 7835 7835, FieldExpression.mul 7836 7836, FieldExpression.mul 7836 7837, FieldExpression.mul 7835 7838] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_245 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7840
      ([FieldExpression.add 4876 7790, FieldExpression.mul 7840 7840, FieldExpression.mul 7841 7841, FieldExpression.mul 7841 7842, FieldExpression.mul 7840 7843, FieldExpression.add 4880 7793, FieldExpression.mul 7845 7845, FieldExpression.mul 7846 7846, FieldExpression.mul 7846 7847, FieldExpression.mul 7845 7848, FieldExpression.add 4884 7796, FieldExpression.mul 7850 7850, FieldExpression.mul 7851 7851, FieldExpression.mul 7851 7852, FieldExpression.mul 7850 7853, FieldExpression.add 4888 7799, FieldExpression.mul 7855 7855, FieldExpression.mul 7856 7856, FieldExpression.mul 7856 7857, FieldExpression.mul 7855 7858, FieldExpression.add 4892 7802, FieldExpression.mul 7860 7860, FieldExpression.mul 7861 7861, FieldExpression.mul 7861 7862, FieldExpression.mul 7860 7863, FieldExpression.add 4896 7805, FieldExpression.mul 7865 7865, FieldExpression.mul 7866 7866, FieldExpression.mul 7866 7867, FieldExpression.mul 7865 7868, FieldExpression.add 4900 7808, FieldExpression.mul 7870 7870] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_246 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7872
      ([FieldExpression.mul 7871 7871, FieldExpression.mul 7871 7872, FieldExpression.mul 7870 7873, FieldExpression.add 4904 7811, FieldExpression.mul 7875 7875, FieldExpression.mul 7876 7876, FieldExpression.mul 7876 7877, FieldExpression.mul 7875 7878, FieldExpression.add 4908 7814, FieldExpression.mul 7880 7880, FieldExpression.mul 7881 7881, FieldExpression.mul 7881 7882, FieldExpression.mul 7880 7883, FieldExpression.add 4912 7817, FieldExpression.mul 7885 7885, FieldExpression.mul 7886 7886, FieldExpression.mul 7886 7887, FieldExpression.mul 7885 7888, FieldExpression.add 4916 7820, FieldExpression.mul 7890 7890, FieldExpression.mul 7891 7891, FieldExpression.mul 7891 7892, FieldExpression.mul 7890 7893, FieldExpression.add 4920 7823, FieldExpression.mul 7895 7895, FieldExpression.mul 7896 7896, FieldExpression.mul 7896 7897, FieldExpression.mul 7895 7898, FieldExpression.add 4924 7826, FieldExpression.mul 7900 7900, FieldExpression.mul 7901 7901, FieldExpression.mul 7901 7902] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_247 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7904
      ([FieldExpression.mul 7900 7903, FieldExpression.add 4928 7829, FieldExpression.mul 7905 7905, FieldExpression.mul 7906 7906, FieldExpression.mul 7906 7907, FieldExpression.mul 7905 7908, FieldExpression.add 7834 7839, FieldExpression.add 7844 7910, FieldExpression.add 7849 7911, FieldExpression.add 7834 7912, FieldExpression.add 7839 7912, FieldExpression.add 7844 7912, FieldExpression.add 7849 7912, FieldExpression.add 7854 7859, FieldExpression.add 7864 7917, FieldExpression.add 7869 7918, FieldExpression.add 7854 7919, FieldExpression.add 7859 7919, FieldExpression.add 7864 7919, FieldExpression.add 7869 7919, FieldExpression.add 7874 7879, FieldExpression.add 7884 7924, FieldExpression.add 7889 7925, FieldExpression.add 7874 7926, FieldExpression.add 7879 7926, FieldExpression.add 7884 7926, FieldExpression.add 7889 7926, FieldExpression.add 7894 7899, FieldExpression.add 7904 7931, FieldExpression.add 7909 7932, FieldExpression.add 7894 7933, FieldExpression.add 7899 7933] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_248 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7936
      ([FieldExpression.add 7904 7933, FieldExpression.add 7909 7933, FieldExpression.add 7913 7920, FieldExpression.add 7927 7934, FieldExpression.add 7938 7939, FieldExpression.add 7920 7940, FieldExpression.add 7934 7940, FieldExpression.add 7913 7913, FieldExpression.add 7942 7943, FieldExpression.add 7927 7927, FieldExpression.add 7941 7945, FieldExpression.add 7938 7941, FieldExpression.add 7939 7942, FieldExpression.add 7914 7921, FieldExpression.add 7928 7935, FieldExpression.add 7949 7950, FieldExpression.add 7921 7951, FieldExpression.add 7935 7951, FieldExpression.add 7914 7914, FieldExpression.add 7953 7954, FieldExpression.add 7928 7928, FieldExpression.add 7952 7956, FieldExpression.add 7949 7952, FieldExpression.add 7950 7953, FieldExpression.add 7915 7922, FieldExpression.add 7929 7936, FieldExpression.add 7960 7961, FieldExpression.add 7922 7962, FieldExpression.add 7936 7962, FieldExpression.add 7915 7915, FieldExpression.add 7964 7965, FieldExpression.add 7929 7929] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_249 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 7968
      ([FieldExpression.add 7963 7967, FieldExpression.add 7960 7963, FieldExpression.add 7961 7964, FieldExpression.add 7916 7923, FieldExpression.add 7930 7937, FieldExpression.add 7971 7972, FieldExpression.add 7923 7973, FieldExpression.add 7937 7973, FieldExpression.add 7916 7916, FieldExpression.add 7975 7976, FieldExpression.add 7930 7930, FieldExpression.add 7974 7978, FieldExpression.add 7971 7974, FieldExpression.add 7972 7975, FieldExpression.sub 755 7947, FieldExpression.sub 756 7958, FieldExpression.sub 757 7969, FieldExpression.sub 758 7980, FieldExpression.sub 759 7946, FieldExpression.sub 760 7957, FieldExpression.sub 761 7968, FieldExpression.sub 762 7979, FieldExpression.sub 763 7948, FieldExpression.sub 764 7959, FieldExpression.sub 765 7970, FieldExpression.sub 766 7981, FieldExpression.sub 767 7944, FieldExpression.sub 768 7955, FieldExpression.sub 769 7966, FieldExpression.sub 770 7977, FieldExpression.sub 780 1, FieldExpression.mul 780 7998] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_250 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8000
      ([FieldExpression.sub 780 2, FieldExpression.mul 7999 8000, FieldExpression.sub 780 829, FieldExpression.mul 8001 8002, FieldExpression.sub 780 1460, FieldExpression.mul 8003 8004, FieldExpression.sub 780 1463, FieldExpression.mul 8005 8006, FieldExpression.sub 780 1466, FieldExpression.mul 8007 8008, FieldExpression.sub 0 1, FieldExpression.mul 7998 8000, FieldExpression.sub 0 2, FieldExpression.mul 8010 8012, FieldExpression.mul 8002 8011, FieldExpression.sub 0 829, FieldExpression.mul 8013 8015, FieldExpression.mul 8004 8014, FieldExpression.sub 0 1460, FieldExpression.mul 8016 8018, FieldExpression.mul 8006 8017, FieldExpression.sub 0 1463, FieldExpression.mul 8019 8021, FieldExpression.mul 8008 8020, FieldExpression.sub 0 1466, FieldExpression.mul 8022 8024, FieldExpression.inverse 8025, FieldExpression.mul 8023 8026, FieldExpression.mul 773 8027, FieldExpression.mul 780 8000, FieldExpression.sub 1 2, FieldExpression.mul 8002 8029] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_251 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8032
      ([FieldExpression.sub 1 829, FieldExpression.mul 8030 8032, FieldExpression.mul 8004 8031, FieldExpression.sub 1 1460, FieldExpression.mul 8033 8035, FieldExpression.mul 8006 8034, FieldExpression.sub 1 1463, FieldExpression.mul 8036 8038, FieldExpression.mul 8008 8037, FieldExpression.sub 1 1466, FieldExpression.mul 8039 8041, FieldExpression.inverse 8042, FieldExpression.mul 8040 8043, FieldExpression.mul 774 8044, FieldExpression.add 8028 8045, FieldExpression.sub 2 1, FieldExpression.mul 2 8047, FieldExpression.mul 7999 8002, FieldExpression.sub 2 829, FieldExpression.mul 8048 8050, FieldExpression.mul 8004 8049, FieldExpression.sub 2 1460, FieldExpression.mul 8051 8053, FieldExpression.mul 8006 8052, FieldExpression.sub 2 1463, FieldExpression.mul 8054 8056, FieldExpression.mul 8008 8055, FieldExpression.sub 2 1466, FieldExpression.mul 8057 8059, FieldExpression.inverse 8060, FieldExpression.mul 8058 8061, FieldExpression.mul 775 8062] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_252 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8064
      ([FieldExpression.add 8046 8063, FieldExpression.sub 829 1, FieldExpression.mul 829 8065, FieldExpression.sub 829 2, FieldExpression.mul 8066 8067, FieldExpression.mul 8001 8004, FieldExpression.sub 829 1460, FieldExpression.mul 8068 8070, FieldExpression.mul 8006 8069, FieldExpression.sub 829 1463, FieldExpression.mul 8071 8073, FieldExpression.mul 8008 8072, FieldExpression.sub 829 1466, FieldExpression.mul 8074 8076, FieldExpression.inverse 8077, FieldExpression.mul 8075 8078, FieldExpression.mul 776 8079, FieldExpression.add 8064 8080, FieldExpression.sub 1460 1, FieldExpression.mul 1460 8082, FieldExpression.sub 1460 2, FieldExpression.mul 8083 8084, FieldExpression.sub 1460 829, FieldExpression.mul 8085 8086, FieldExpression.mul 8003 8006, FieldExpression.sub 1460 1463, FieldExpression.mul 8087 8089, FieldExpression.mul 8008 8088, FieldExpression.sub 1460 1466, FieldExpression.mul 8090 8092, FieldExpression.inverse 8093, FieldExpression.mul 8091 8094] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_253 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8096
      ([FieldExpression.mul 777 8095, FieldExpression.add 8081 8096, FieldExpression.sub 1463 1, FieldExpression.mul 1463 8098, FieldExpression.sub 1463 2, FieldExpression.mul 8099 8100, FieldExpression.sub 1463 829, FieldExpression.mul 8101 8102, FieldExpression.sub 1463 1460, FieldExpression.mul 8103 8104, FieldExpression.mul 8005 8008, FieldExpression.sub 1463 1466, FieldExpression.mul 8105 8107, FieldExpression.inverse 8108, FieldExpression.mul 8106 8109, FieldExpression.mul 778 8110, FieldExpression.add 8097 8111, FieldExpression.sub 1466 1, FieldExpression.mul 1466 8113, FieldExpression.sub 1466 2, FieldExpression.mul 8114 8115, FieldExpression.sub 1466 829, FieldExpression.mul 8116 8117, FieldExpression.sub 1466 1460, FieldExpression.mul 8118 8119, FieldExpression.sub 1466 1463, FieldExpression.mul 8120 8121, FieldExpression.inverse 8122, FieldExpression.mul 8007 8123, FieldExpression.mul 779 8124, FieldExpression.add 8112 8125, FieldExpression.mul 781 8126] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_254 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8128
      ([FieldExpression.sub 8127 1, FieldExpression.sub 782 1, FieldExpression.mul 782 8129, FieldExpression.mul 784 785, FieldExpression.sub 8131 786, FieldExpression.sub 787 1, FieldExpression.sub 787 2, FieldExpression.sub 787 829, FieldExpression.mul 787 8133, FieldExpression.mul 8134 8136, FieldExpression.mul 8135 8137, FieldExpression.sub 788 1, FieldExpression.sub 788 2, FieldExpression.sub 788 829, FieldExpression.mul 788 8139, FieldExpression.mul 8140 8142, FieldExpression.mul 8141 8143, FieldExpression.sub 789 1, FieldExpression.sub 789 2, FieldExpression.sub 789 829, FieldExpression.mul 789 8145, FieldExpression.mul 8146 8148, FieldExpression.mul 8147 8149, FieldExpression.sub 790 1, FieldExpression.sub 790 2, FieldExpression.sub 790 829, FieldExpression.mul 790 8151, FieldExpression.mul 8152 8154, FieldExpression.mul 8153 8155, FieldExpression.sub 791 1, FieldExpression.sub 791 2, FieldExpression.sub 791 829] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_255 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8160
      ([FieldExpression.mul 791 8157, FieldExpression.mul 8158 8160, FieldExpression.mul 8159 8161, FieldExpression.sub 792 1, FieldExpression.sub 792 2, FieldExpression.sub 792 829, FieldExpression.mul 792 8163, FieldExpression.mul 8164 8166, FieldExpression.mul 8165 8167, FieldExpression.sub 793 1, FieldExpression.sub 793 2, FieldExpression.sub 793 829, FieldExpression.mul 793 8169, FieldExpression.mul 8170 8172, FieldExpression.mul 8171 8173, FieldExpression.sub 794 1, FieldExpression.sub 794 2, FieldExpression.sub 794 829, FieldExpression.mul 794 8175, FieldExpression.mul 8176 8178, FieldExpression.mul 8177 8179, FieldExpression.sub 795 1, FieldExpression.sub 795 2, FieldExpression.sub 795 829, FieldExpression.mul 795 8181, FieldExpression.mul 8182 8184, FieldExpression.mul 8183 8185, FieldExpression.sub 796 1, FieldExpression.sub 796 2, FieldExpression.sub 796 829, FieldExpression.mul 796 8187, FieldExpression.mul 8188 8190] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_256 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8192
      ([FieldExpression.mul 8189 8191, FieldExpression.sub 797 1, FieldExpression.sub 797 2, FieldExpression.sub 797 829, FieldExpression.mul 797 8193, FieldExpression.mul 8194 8196, FieldExpression.mul 8195 8197, FieldExpression.sub 798 1, FieldExpression.sub 798 2, FieldExpression.sub 798 829, FieldExpression.mul 798 8199, FieldExpression.mul 8200 8202, FieldExpression.mul 8201 8203, FieldExpression.sub 799 1, FieldExpression.sub 799 2, FieldExpression.sub 799 829, FieldExpression.mul 799 8205, FieldExpression.mul 8206 8208, FieldExpression.mul 8207 8209, FieldExpression.sub 800 1, FieldExpression.sub 800 2, FieldExpression.sub 800 829, FieldExpression.mul 800 8211, FieldExpression.mul 8212 8214, FieldExpression.mul 8213 8215, FieldExpression.sub 801 1, FieldExpression.sub 801 2, FieldExpression.sub 801 829, FieldExpression.mul 801 8217, FieldExpression.mul 8218 8220, FieldExpression.mul 8219 8221, FieldExpression.sub 802 1] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_257 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8224
      ([FieldExpression.sub 802 2, FieldExpression.sub 802 829, FieldExpression.mul 802 8223, FieldExpression.mul 8224 8226, FieldExpression.mul 8225 8227, FieldExpression.sub 803 1, FieldExpression.sub 803 2, FieldExpression.sub 803 829, FieldExpression.mul 803 8229, FieldExpression.mul 8230 8232, FieldExpression.mul 8231 8233, FieldExpression.sub 804 1, FieldExpression.sub 804 2, FieldExpression.sub 804 829, FieldExpression.mul 804 8235, FieldExpression.mul 8236 8238, FieldExpression.mul 8237 8239, FieldExpression.sub 805 1, FieldExpression.sub 805 2, FieldExpression.sub 805 829, FieldExpression.mul 805 8241, FieldExpression.mul 8242 8244, FieldExpression.mul 8243 8245, FieldExpression.sub 806 1, FieldExpression.sub 806 2, FieldExpression.sub 806 829, FieldExpression.mul 806 8247, FieldExpression.mul 8248 8250, FieldExpression.mul 8249 8251, FieldExpression.sub 807 1, FieldExpression.sub 807 2, FieldExpression.sub 807 829] : List FieldExpression) = true := by
  decide

private theorem exact_degree_chunk_258 :
    checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 8256
      ([FieldExpression.mul 807 8253, FieldExpression.mul 8254 8256, FieldExpression.mul 8255 8257, FieldExpression.sub 808 1, FieldExpression.sub 808 2, FieldExpression.sub 808 829, FieldExpression.mul 808 8259, FieldExpression.mul 8260 8262, FieldExpression.mul 8261 8263, FieldExpression.sub 809 1, FieldExpression.sub 809 2, FieldExpression.sub 809 829, FieldExpression.mul 809 8265, FieldExpression.mul 8266 8268, FieldExpression.mul 8267 8269] : List FieldExpression) = true := by
  decide

theorem exact_degree_certificate : DegreeCertificate exactNonlinearExpressions exactDegree := by
  have checked : checkIndexed (fun node expression => decide
      (expressionDegree exactDegree expression ≤ exactDegree node ∧
        expressionSafe exactDegree expression)) 0 exactNonlinearExpressions = true := by
    unfold exactNonlinearExpressions
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_000
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_001
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_002
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_003
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_004
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_005
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_006
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_007
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_008
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_009
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_010
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_011
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_012
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_013
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_014
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_015
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_016
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_017
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_018
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_019
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_020
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_021
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_022
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_023
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_024
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_025
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_026
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_027
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_028
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_029
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_030
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_031
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_032
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_033
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_034
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_035
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_036
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_037
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_038
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_039
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_040
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_041
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_042
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_043
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_044
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_045
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_046
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_047
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_048
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_049
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_050
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_051
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_052
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_053
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_054
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_055
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_056
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_057
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_058
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_059
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_060
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_061
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_062
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_063
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_064
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_065
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_066
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_067
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_068
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_069
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_070
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_071
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_072
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_073
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_074
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_075
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_076
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_077
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_078
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_079
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_080
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_081
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_082
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_083
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_084
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_085
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_086
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_087
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_088
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_089
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_090
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_091
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_092
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_093
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_094
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_095
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_096
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_097
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_098
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_099
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_100
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_101
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_102
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_103
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_104
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_105
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_106
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_107
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_108
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_109
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_110
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_111
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_112
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_113
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_114
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_115
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_116
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_117
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_118
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_119
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_120
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_121
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_122
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_123
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_124
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_125
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_126
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_127
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_128
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_129
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_130
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_131
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_132
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_133
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_134
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_135
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_136
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_137
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_138
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_139
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_140
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_141
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_142
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_143
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_144
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_145
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_146
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_147
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_148
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_149
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_150
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_151
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_152
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_153
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_154
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_155
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_156
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_157
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_158
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_159
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_160
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_161
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_162
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_163
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_164
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_165
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_166
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_167
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_168
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_169
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_170
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_171
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_172
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_173
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_174
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_175
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_176
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_177
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_178
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_179
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_180
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_181
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_182
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_183
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_184
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_185
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_186
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_187
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_188
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_189
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_190
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_191
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_192
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_193
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_194
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_195
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_196
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_197
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_198
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_199
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_200
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_201
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_202
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_203
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_204
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_205
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_206
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_207
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_208
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_209
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_210
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_211
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_212
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_213
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_214
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_215
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_216
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_217
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_218
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_219
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_220
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_221
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_222
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_223
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_224
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_225
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_226
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_227
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_228
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_229
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_230
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_231
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_232
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_233
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_234
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_235
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_236
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_237
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_238
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_239
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_240
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_241
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_242
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_243
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_244
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_245
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_246
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_247
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_248
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_249
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_250
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_251
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_252
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_253
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_254
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_255
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_256
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_257
    apply checkIndexed_flatten_cons
    · exact exact_degree_chunk_258
    rfl
  exact degreeCertificate_of_checkIndexed exactNonlinearExpressions exactDegree checked

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
