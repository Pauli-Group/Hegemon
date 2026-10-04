import SmzaRp05RelationDslBase
import HegemonCrypto.SmallWoodV8Smz9CurrentSourceAcceptance
import Lean.Elab.Tactic.Omega

/-!
# Generic normalization of the current public CSR attempts

This module mirrors the executable normalization algorithm.  A raw row is
discarded exactly when every coefficient and its target are zero.  A retained
row with an empty raw coefficient vector uses the Rust fallback source cell
41528; otherwise its raw coefficients are retained.  Consequently the
`retainedOrZeroOrFallback` classification is a theorem of `List.filter`, not a
generated proposition quantified over all public statements or witnesses.

The generated artifact still supplies finite canonicality, coordinate, root,
and node-degree facts.  It also identifies one independently retained
`e_41528 = 0` raw attempt.  No witness-semantic implication is a certificate.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CsrNormalization

open Polynomial
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9CurrentPublicContext
open SmzaRp05StatementNamespace SmzaRp05TracePrefixes
open SmzaRp05RelationRefinement
open V8Smz9ProgramPolynomials
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

def values (components : RelationProgramComponents) (statement : Statement) : List Nat :=
  (evalExpressionNodes (currentPublicWords statement) []
    components.csrExpressions).getD []

/-- Canonical public-only DAGs evaluate on every fixed-length statement.
The interpreter normalizes individual public words, so this does not assume
that arbitrary statement bytes already satisfy the verifier's field checks. -/
theorem values_evaluation_succeeds
    (components : RelationProgramComponents)
    (canonical : ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical false)
    (statement : Statement) :
    evalExpressionNodes (SmzaRp05TracePrefixes.publicWords statement) []
      components.csrExpressions = some (values components statement) := by
  obtain ⟨result, evaluated, _⟩ :=
    V8Smz9CurrentSourceAcceptance.canonical_expression_program_resolves
      (SmzaRp05TracePrefixes.publicWords statement) []
      { expressions := components.csrExpressions, roots := [] } false
      (by simp [SmzaRp05TracePrefixes.public_words_length, publicStatementWordCount])
      (by simp) canonical
  simp only [values, currentPublicWords, evaluated, Option.getD_some]

/-- The zero/one coefficient facts are consequences of two finite DAG
lookups, not generated propositions universally quantified over statements. -/
theorem values_at_constant
    (components : RelationProgramComponents)
    (canonical : ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical false)
    (statement : Statement) (index constant : Nat)
    (found : components.csrExpressions[index]? = some (.constant constant)) :
    (values components statement).getD index 0 = constant := by
  have canonicalRows :
      ({ expressions := components.csrExpressions, roots := [] } :
        ExpressionProgram).Canonical true := by
    constructor
    · intro node expression member
      exact V8Smz9SemanticBinding.canonical_without_rows_allows_rows
        (canonical.1 node expression member)
    · simp
  have equation :=
    V8Smz9SemanticBinding.evaluated_program_satisfies_each_node canonicalRows
      (values_evaluation_succeeds components canonical statement) found
  have bound : constant < fieldModulus := canonical.1 index (.constant constant) found
  simp only [List.getD_eq_getElem?_getD, equation, evalFieldExpression,
    Option.getD_some, fieldNormalize, Nat.mod_eq_of_lt bound]

def rawCoefficient (components : RelationProgramComponents) (statement : Statement)
    (attempt : CsrExecutableAttempt) (index : Fin 43904) : Goldilocks :=
  denseCoefficient (values components statement) attempt.terms index

def rawTarget (components : RelationProgramComponents) (statement : Statement)
    (attempt : CsrExecutableAttempt) : Goldilocks :=
  ((values components statement).getD attempt.targetRoot 0 : Goldilocks)

def rawEmpty (components : RelationProgramComponents) (statement : Statement)
    (attempt : CsrExecutableAttempt) : Prop :=
  ∀ index : Fin 43904, rawCoefficient components statement attempt index = 0

instance rawEmptyDecidable (components : RelationProgramComponents)
    (statement : Statement) (attempt : CsrExecutableAttempt) :
    Decidable (rawEmpty components statement attempt) := by
  unfold rawEmpty
  infer_instance

def rowEmitted (components : RelationProgramComponents) (statement : Statement)
    (attempt : CsrExecutableAttempt) : Prop :=
  ¬(rawEmpty components statement attempt ∧ rawTarget components statement attempt = 0)

instance rowEmittedDecidable (components : RelationProgramComponents)
    (statement : Statement) (attempt : CsrExecutableAttempt) :
    Decidable (rowEmitted components statement attempt) := by
  unfold rowEmitted
  infer_instance

def retained (components : RelationProgramComponents) (statement : Statement) :
    List CsrExecutableAttempt :=
  components.csrAttempts.filter fun attempt => decide (rowEmitted components statement attempt)

def normalizedCoefficient (components : RelationProgramComponents)
    (statement : Statement) (attempt : CsrExecutableAttempt)
    (index : Fin 43904) : Goldilocks :=
  if rawEmpty components statement attempt then zeroSourceCoefficient index
  else rawCoefficient components statement attempt index

/-- Current relation DSL: 818 nonlinear roots and exactly the public-dependent
retained normalized rows. -/
def normalizedDsl (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat) : RelationDsl where
  components := components
  nonlinearCount := 818
  linearCount statement := (retained components statement).length
  nonlinearRoot := nonlinearRoot
  nodeDegree := nodeDegree
  linearWeights statement row witnessRow lane :=
    normalizedCoefficient components statement
      (retained components statement)[row.val]
      (finProdFinEquiv (witnessRow, lane))
  linearTarget statement row :=
    rawTarget components statement (retained components statement)[row.val]

theorem normalized_dsl_width (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (statement : Statement) :
    (normalizedDsl components nonlinearRoot nodeDegree).width statement =
      max 818 (retained components statement).length := rfl

/-- An ex-ante bound depends only on the fixed artifact's attempt count,
never on the selected statement or final accepted batch. -/
theorem normalized_dsl_width_le_attempt_bound
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (bound : Nat) (nonlinearBound : 818 ≤ bound)
    (attemptBound : components.csrAttempts.length ≤ bound)
    (statement : Statement) :
    (normalizedDsl components nonlinearRoot nodeDegree).width statement ≤ bound := by
  rw [normalized_dsl_width]
  apply max_le nonlinearBound
  exact (List.length_filter_le _ _).trans attemptBound

theorem retained_member_iff (components : RelationProgramComponents)
    (statement : Statement) (attempt : CsrExecutableAttempt) :
    attempt ∈ retained components statement ↔
      attempt ∈ components.csrAttempts ∧ rowEmitted components statement attempt := by
  simp [retained]

theorem normalized_row_coefficient_eq
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (statement : Statement)
    (row : Fin (retained components statement).length) (index : Fin 43904) :
    normalizedRowCoefficient (normalizedDsl components nonlinearRoot nodeDegree)
      statement row index =
        normalizedCoefficient components statement
          (retained components statement)[row.val] index := by
  simp [normalizedRowCoefficient, normalizedDsl]

theorem normalized_linear_target_eq
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (statement : Statement)
    (row : Fin (retained components statement).length) :
    (normalizedDsl components nonlinearRoot nodeDegree).linearTarget statement row =
      rawTarget components statement
        (retained components statement)[row.val] := rfl

/-- Classification of raw attempts before semantic reasoning. An empty row
with a nonzero target is not coefficient-equal to its retained fallback:
it uses the third alternative explicitly. -/
theorem retained_or_zero_or_fallback
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (statement : Statement) (attempt : CsrExecutableAttempt)
    (member : attempt ∈ components.csrAttempts) :
    (∃ row : Fin ((normalizedDsl components nonlinearRoot nodeDegree).linearCount statement),
      (∀ index : Fin 43904,
        executableCoefficient (normalizedDsl components nonlinearRoot nodeDegree)
            statement attempt index =
          normalizedRowCoefficient (normalizedDsl components nonlinearRoot nodeDegree)
            statement row index) ∧
      executableTarget (normalizedDsl components nonlinearRoot nodeDegree)
          statement attempt =
        (normalizedDsl components nonlinearRoot nodeDegree).linearTarget statement row) ∨
    ((∀ index : Fin 43904,
      executableCoefficient (normalizedDsl components nonlinearRoot nodeDegree)
        statement attempt index = 0) ∧
      executableTarget (normalizedDsl components nonlinearRoot nodeDegree)
        statement attempt = 0) ∨
    ((∀ index : Fin 43904,
      executableCoefficient (normalizedDsl components nonlinearRoot nodeDegree)
        statement attempt index = 0) ∧
      executableTarget (normalizedDsl components nonlinearRoot nodeDegree)
        statement attempt ≠ 0 ∧
      ∃ row : Fin ((normalizedDsl components nonlinearRoot nodeDegree).linearCount statement),
        (∀ index, normalizedRowCoefficient
          (normalizedDsl components nonlinearRoot nodeDegree) statement row index =
            zeroSourceCoefficient index) ∧
        (normalizedDsl components nonlinearRoot nodeDegree).linearTarget statement row =
          executableTarget (normalizedDsl components nonlinearRoot nodeDegree)
            statement attempt) := by
  by_cases emitted : rowEmitted components statement attempt
  · have retainedMember : attempt ∈ retained components statement :=
      (retained_member_iff components statement attempt).2 ⟨member, emitted⟩
    obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp retainedMember
    have bound : index < (retained components statement).length :=
      List.getElem?_eq_some_iff.mp found |>.1
    let row : Fin (retained components statement).length := ⟨index, bound⟩
    have selected : (retained components statement)[row.val] = attempt :=
      (List.getElem?_eq_some_iff.mp found).2
    have target : executableTarget (normalizedDsl components nonlinearRoot nodeDegree)
        statement attempt =
        (normalizedDsl components nonlinearRoot nodeDegree).linearTarget statement row := by
      simp [executableTarget, csrValues, normalizedDsl, values, rawTarget, selected]
    by_cases empty : rawEmpty components statement attempt
    · right
      right
      refine ⟨?_, ?_, row, ?_, target.symm⟩
      · intro coordinate
        simpa [executableCoefficient, csrValues, normalizedDsl, values,
          rawCoefficient] using empty coordinate
      · intro targetZero
        apply emitted
        exact ⟨empty, by simpa [executableTarget, csrValues, normalizedDsl,
          values, rawTarget] using targetZero⟩
      · intro coordinate
        rw [normalized_row_coefficient_eq, selected]
        exact if_pos empty
    · left
      refine ⟨row, ?_, target⟩
      intro coordinate
      rw [normalized_row_coefficient_eq, selected]
      simp [executableCoefficient, csrValues, normalizedDsl, values,
        normalizedCoefficient, empty, rawCoefficient]
  · right
    left
    have discarded : rawEmpty components statement attempt ∧
        rawTarget components statement attempt = 0 := by
      simpa [rowEmitted] using emitted
    constructor
    · intro index
      simpa [executableCoefficient, csrValues, normalizedDsl, values,
        rawCoefficient] using discarded.1 index
    · simpa [executableTarget, csrValues, normalizedDsl, values, rawTarget]
        using discarded.2

/-- A finite identified raw row `e_41528 = 0` is retained for every public
statement and supplies the independently constrained zero-source row. -/
theorem zero_source_row_of_raw_attempt
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (zeroAttempt : CsrExecutableAttempt)
    (zeroMember : zeroAttempt ∈ components.csrAttempts)
    (zeroTerms : zeroAttempt.terms = [(41528, 1)])
    (zeroTargetRoot : zeroAttempt.targetRoot = 0)
    (valuesZero : ∀ statement, (values components statement).getD 0 0 = 0)
    (valuesOne : ∀ statement, (values components statement).getD 1 0 = 1) :
    ∀ statement : Statement,
      ∃ row : Fin ((normalizedDsl components nonlinearRoot nodeDegree).linearCount statement),
        (∀ index, normalizedRowCoefficient
          (normalizedDsl components nonlinearRoot nodeDegree) statement row index =
            zeroSourceCoefficient index) ∧
        (normalizedDsl components nonlinearRoot nodeDegree).linearTarget
          statement row = 0 := by
  intro statement
  have zeroCoefficients : ∀ index,
      rawCoefficient components statement zeroAttempt index =
        zeroSourceCoefficient index := by
    intro index
    by_cases same : index.val = 41528
    · simp [rawCoefficient, denseCoefficient, zeroTerms, zeroSourceCoefficient,
        same, -List.getD_eq_getElem?_getD, valuesOne statement]
    · simp [rawCoefficient, denseCoefficient, zeroTerms, zeroSourceCoefficient,
        same, Ne.symm same]
  have zeroTarget : rawTarget components statement zeroAttempt = 0 := by
    simp [rawTarget, zeroTargetRoot, -List.getD_eq_getElem?_getD,
      valuesZero statement]
  have nonempty : ¬ rawEmpty components statement zeroAttempt := by
    intro empty
    let coordinate : Fin 43904 := ⟨41528, by omega⟩
    have zero := empty coordinate
    have one : zeroSourceCoefficient coordinate = 1 := by
      simp [zeroSourceCoefficient, coordinate]
    have impossible : (1 : Goldilocks) = 0 := by
      calc
        1 = zeroSourceCoefficient coordinate := one.symm
        _ = rawCoefficient components statement zeroAttempt coordinate :=
          (zeroCoefficients coordinate).symm
        _ = 0 := zero
    exact one_ne_zero impossible
  have emitted : rowEmitted components statement zeroAttempt := by
    simp [rowEmitted, nonempty]
  have retainedMember : zeroAttempt ∈ retained components statement :=
    (retained_member_iff components statement zeroAttempt).2 ⟨zeroMember, emitted⟩
  obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp retainedMember
  have bound : index < (retained components statement).length :=
    List.getElem?_eq_some_iff.mp found |>.1
  let row : Fin (retained components statement).length := ⟨index, bound⟩
  refine ⟨row, ?_, ?_⟩
  · intro coordinate
    have selected : (retained components statement)[row.val] = zeroAttempt :=
      (List.getElem?_eq_some_iff.mp found).2
    rw [normalized_row_coefficient_eq, selected]
    simp [normalizedCoefficient, nonempty, zeroCoefficients]
  · have selected : (retained components statement)[row.val] = zeroAttempt :=
      (List.getElem?_eq_some_iff.mp found).2
    simpa [normalizedDsl, selected] using zeroTarget

/-- Assemble the CSR certificate from finite syntax facts and the one retained
zero-source attempt. All three normalization alternatives are derived by
filtering, including the distinct impossible-empty fallback. -/
theorem csrCertificate
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (programCanonical :
      ({ expressions := components.csrExpressions, roots := [] } :
        ExpressionProgram).Canonical false)
    (attemptCoordinates : ∀ attempt, attempt ∈ components.csrAttempts →
      (∀ term, term ∈ attempt.terms →
        term.1 < 43904 ∧ term.2 < components.csrExpressions.length) ∧
      attempt.targetRoot < components.csrExpressions.length)
    (zeroAttempt : CsrExecutableAttempt)
    (zeroMember : zeroAttempt ∈ components.csrAttempts)
    (zeroTerms : zeroAttempt.terms = [(41528, 1)])
    (zeroTargetRoot : zeroAttempt.targetRoot = 0)
    (zeroNode : components.csrExpressions[0]? = some (.constant 0))
    (oneNode : components.csrExpressions[1]? = some (.constant 1)) :
    CsrCertificate (normalizedDsl components nonlinearRoot nodeDegree) where
  programCanonical := programCanonical
  attemptCoordinates := attemptCoordinates
  zeroSourceRow := zero_source_row_of_raw_attempt components nonlinearRoot nodeDegree
    zeroAttempt zeroMember zeroTerms zeroTargetRoot
    (fun statement => values_at_constant components programCanonical statement 0 0 zeroNode)
    (fun statement => values_at_constant components programCanonical statement 1 1 oneNode)
  retainedOrZeroOrFallback statement attempt member := by
    exact retained_or_zero_or_fallback components nonlinearRoot nodeDegree
      statement attempt member

end
end HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
