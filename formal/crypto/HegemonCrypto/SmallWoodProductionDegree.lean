import Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-!
# Production nonlinear-program degree semantics

This module contains the small, generic degree interpreter used by the generated
SmallWood production certificate.  The certificate is checked in bounded chunks
and then composed into one theorem about the complete generated program.
-/

namespace HegemonCrypto.SmallWood.ProductionPolynomials

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-- Formal degree operation paired instruction-for-instruction with the polynomial interpreter. -/
def expressionFormalDegree
    (values : Array Nat) :
    ProductionConstraintExpression -> Nat
  | .constExpr _ | .publicExpr _ | .slotInverseExpr _ | .stableSelectorExpr _ => 0
  | .witnessExpr _ => 1
  | .addExpr left right | .subExpr left right =>
      max (values.getD left 0) (values.getD right 0)
  | .mulExpr left right => values.getD left 0 + values.getD right 0
  | .negExpr value => values.getD value 0

/-- Execute the formal degree program from an arbitrary already-checked prefix. -/
def formalDegreeProgramFrom
    (initial : Array Nat)
    (expressions : List ProductionConstraintExpression) : Array Nat :=
  expressions.foldl
    (fun values expression =>
      values.push (expressionFormalDegree values expression))
    initial

/-- Execute the complete formal degree program. -/
def formalDegreeProgram
    (expressions : List ProductionConstraintExpression) : Array Nat :=
  formalDegreeProgramFrom #[] expressions

def chunkedDegreeAt
    (chunks : List (List Nat))
    (chunkSize index : Nat) : Nat :=
  (chunks.getD (index / chunkSize) []).getD (index % chunkSize) 0

def expressionFormalDegreeAt
    (degreeAt : Nat -> Nat) :
    ProductionConstraintExpression -> Nat
  | .constExpr _ | .publicExpr _ | .slotInverseExpr _ | .stableSelectorExpr _ => 0
  | .witnessExpr _ => 1
  | .addExpr left right | .subExpr left right =>
      max (degreeAt left) (degreeAt right)
  | .mulExpr left right => degreeAt left + degreeAt right
  | .negExpr value => degreeAt value

def expressionReferencesBeforeB
    (offset : Nat)
    (expression : ProductionConstraintExpression) : Bool :=
  expression.references.all fun reference => decide (reference < offset)

def formalDegreeCertificateAtB
    (degreeAt : Nat -> Nat) :
    Nat -> List ProductionConstraintExpression -> Bool
  | _, [] => true
  | offset, expression :: expressions =>
      expressionReferencesBeforeB offset expression &&
        (decide (expressionFormalDegreeAt degreeAt expression = degreeAt offset) &&
          formalDegreeCertificateAtB degreeAt (offset + 1) expressions)

theorem expression_references_before_of_checked
    (offset : Nat)
    (expression : ProductionConstraintExpression)
    (checked : expressionReferencesBeforeB offset expression = true) :
    ∀ reference, reference ∈ expression.references -> reference < offset := by
  intro reference membership
  exact of_decide_eq_true <|
    (List.all_eq_true.mp checked) reference membership

theorem expressionFormalDegree_eq_at_of_agreement
    (values : Array Nat)
    (degreeAt : Nat -> Nat)
    (expression : ProductionConstraintExpression)
    (agreement :
      ∀ reference, reference ∈ expression.references ->
        values.getD reference 0 = degreeAt reference) :
    expressionFormalDegree values expression =
      expressionFormalDegreeAt degreeAt expression := by
  cases expression <;>
    simp [expressionFormalDegree, expressionFormalDegreeAt,
      ProductionConstraintExpression.references, agreement]

private theorem degree_array_getD_push_lt
    {Value : Type}
    (values : Array Value)
    (pushed fallback : Value)
    (index : Nat)
    (indexBound : index < values.size) :
    (values.push pushed).getD index fallback =
      values.getD index fallback := by
  have pushedBound : index < (values.push pushed).size := by
    simp
    omega
  simp only [Array.getD]
  rw [dif_pos pushedBound, dif_pos indexBound]
  exact Array.getElem_push_lt indexBound

private theorem degree_array_getD_push_eq
    {Value : Type}
    (values : Array Value)
    (pushed fallback : Value) :
    (values.push pushed).getD values.size fallback = pushed := by
  simp [Array.getD, Array.getElem_push_eq]

def DegreePrefixAgreement
    (values : Array Nat)
    (degreeAt : Nat -> Nat)
    (offset : Nat) : Prop :=
  values.size = offset ∧
    ∀ index, index < offset -> values.getD index 0 = degreeAt index

theorem degreePrefixAgreement_push
    (values : Array Nat)
    (degreeAt : Nat -> Nat)
    (offset : Nat)
    (expression : ProductionConstraintExpression)
    (agreement : DegreePrefixAgreement values degreeAt offset)
    (referencesBefore :
      ∀ reference, reference ∈ expression.references -> reference < offset)
    (certificateEquation :
      expressionFormalDegreeAt degreeAt expression = degreeAt offset) :
    DegreePrefixAgreement
      (values.push (expressionFormalDegree values expression))
      degreeAt (offset + 1) := by
  constructor
  · simp [agreement.1]
  · intro index indexBound
    by_cases oldIndex : index < offset
    · have arrayBound : index < values.size := by
        simpa [agreement.1] using oldIndex
      rw [degree_array_getD_push_lt _ _ _ _ arrayBound]
      exact agreement.2 index oldIndex
    · have atEnd : index = offset := by omega
      subst index
      have expressionAgreement :
          expressionFormalDegree values expression =
            expressionFormalDegreeAt degreeAt expression :=
        expressionFormalDegree_eq_at_of_agreement
          values degreeAt expression fun reference membership =>
            agreement.2 reference (referencesBefore reference membership)
      calc
        (values.push (expressionFormalDegree values expression)).getD offset 0 =
            (values.push (expressionFormalDegree values expression)).getD
              values.size 0 := by rw [agreement.1]
        _ = expressionFormalDegree values expression :=
          degree_array_getD_push_eq _ _ _
        _ = expressionFormalDegreeAt degreeAt expression := expressionAgreement
        _ = degreeAt offset := certificateEquation

theorem formalDegreeProgramFrom_certificate_sound
    (initial : Array Nat)
    (degreeAt : Nat -> Nat)
    (offset : Nat)
    (expressions : List ProductionConstraintExpression)
    (agreement : DegreePrefixAgreement initial degreeAt offset)
    (checked : formalDegreeCertificateAtB degreeAt offset expressions = true) :
    DegreePrefixAgreement
      (formalDegreeProgramFrom initial expressions)
      degreeAt (offset + expressions.length) := by
  induction expressions generalizing initial offset with
  | nil =>
      simpa [formalDegreeProgramFrom] using agreement
  | cons expression expressions inductionHypothesis =>
      simp only [formalDegreeCertificateAtB, Bool.and_eq_true,
        decide_eq_true_eq] at checked
      rcases checked with
        ⟨referencesChecked, certificateEquation, remainderChecked⟩
      have referencesBefore :=
        expression_references_before_of_checked
          offset expression referencesChecked
      have nextAgreement :=
        degreePrefixAgreement_push initial degreeAt offset expression
          agreement referencesBefore certificateEquation
      have remainderAgreement :=
        inductionHypothesis
          (initial.push (expressionFormalDegree initial expression))
          (offset + 1) nextAgreement remainderChecked
      change DegreePrefixAgreement
        (formalDegreeProgramFrom
          (initial.push (expressionFormalDegree initial expression))
          expressions)
        degreeAt (offset + (expressions.length + 1))
      have offsetArithmetic :
          offset + 1 + expressions.length =
            offset + (expressions.length + 1) := by omega
      rw [← offsetArithmetic]
      exact remainderAgreement

theorem formalDegreeProgram_getD_eq_of_certificate
    (degreeAt : Nat -> Nat)
    (expressions : List ProductionConstraintExpression)
    (checked : formalDegreeCertificateAtB degreeAt 0 expressions = true)
    (index : Nat)
    (indexBound : index < expressions.length) :
    (formalDegreeProgram expressions).getD index 0 = degreeAt index := by
  have initialAgreement : DegreePrefixAgreement #[] degreeAt 0 := by
    simp [DegreePrefixAgreement]
  have finalAgreement :=
    formalDegreeProgramFrom_certificate_sound
      #[] degreeAt 0 expressions initialAgreement checked
  exact finalAgreement.2 index (by simpa using indexBound)

theorem formalDegreeCertificateAtB_append
    (degreeAt : Nat -> Nat)
    (offset : Nat)
    (left right : List ProductionConstraintExpression) :
    formalDegreeCertificateAtB degreeAt offset (left ++ right) =
      (formalDegreeCertificateAtB degreeAt offset left &&
        formalDegreeCertificateAtB degreeAt (offset + left.length) right) := by
  induction left generalizing offset with
  | nil => simp [formalDegreeCertificateAtB]
  | cons expression expressions inductionHypothesis =>
      simp only [List.cons_append, formalDegreeCertificateAtB, List.length_cons]
      rw [inductionHypothesis]
      simp only [Bool.and_assoc]
      have offsetArithmetic :
          offset + 1 + expressions.length =
            offset + (expressions.length + 1) := by omega
      rw [offsetArithmetic]

theorem formalDegreeCertificateAtB_drop_step
    (degreeAt : Nat -> Nat)
    (expressions : List ProductionConstraintExpression)
    (start count : Nat)
    (chunkLength :
      ((expressions.drop start).take count).length = count)
    (chunkChecked :
      formalDegreeCertificateAtB degreeAt start
        ((expressions.drop start).take count) = true)
    (remainderChecked :
      formalDegreeCertificateAtB degreeAt (start + count)
        (expressions.drop (start + count)) = true) :
    formalDegreeCertificateAtB degreeAt start
      (expressions.drop start) = true := by
  rw [← List.take_append_drop count (expressions.drop start)]
  rw [formalDegreeCertificateAtB_append, chunkLength, List.drop_drop]
  simp [chunkChecked, remainderChecked]

end HegemonCrypto.SmallWood.ProductionPolynomials
