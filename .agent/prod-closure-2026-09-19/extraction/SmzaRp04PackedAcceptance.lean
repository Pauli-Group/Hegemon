import SmzaRp04NonlinearTransport
import HegemonCrypto.SmallWoodV8Smz9CurrentSourceAcceptance
import SmzaRp04PackedAcceptanceChecks

/-! Source-specific RP04 normalized CSR and packed interpreter endpoint.
All expression and coordinate facts refer to the new generated components.
The fallback row moved from attempt19298/family39 to19295/family45; it is checked
against actual RP04 bytes. No old relation-validity theorem is imported as evidence.
-/
namespace HegemonCrypto.SmallWood.SmzaRp04PackedAcceptance
open Hegemon.Transaction.Poseidon2V8RelationProgram
open SmzaRp04Components
open V8Smz9ProgramPolynomials V8Smz9ProgramCanonicality
open V8Smz9SemanticBinding V8Smz9SemanticDenseRange
open V8Smz9CurrentPublicContext (PackedIndex packedFieldValues denseCoefficient dense_coefficient_dot)
open V8Smz9CurrentSourceAcceptance (canonical_expression_program_resolves
  field_csr_equation_supplies_source_acceptance field_roots_zero_supplies_source_acceptance)
open scoped BigOperators Classical
noncomputable section
set_option maxRecDepth 10000
set_option maxHeartbeats 800000

private theorem exact_nonlinear_expressions_length :
    exactNonlinearExpressions.length = 8130 := by
  have flattened : SmzaRp04PackedAcceptanceData.nonlinearChunks.flatten =
      exactNonlinearExpressions := by
    unfold exactNonlinearExpressions
    apply congrArg List.flatten
    rfl
  rw [← flattened]
  simp only [SmzaRp04PackedAcceptanceData.nonlinearChunks, List.flatten_append,
    List.length_append,
    SmzaRp04PackedCanonicalPart00.nonlinearChunks00_flatten_length,
    SmzaRp04PackedCanonicalPart01.nonlinearChunks01_flatten_length,
    SmzaRp04PackedCanonicalPart02.nonlinearChunks02_flatten_length,
    SmzaRp04PackedCanonicalPart03.nonlinearChunks03_flatten_length,
    SmzaRp04PackedCanonicalPart04.nonlinearChunks04_flatten_length,
    SmzaRp04PackedCanonicalPart05.nonlinearChunks05_flatten_length,
    Nat.reduceAdd]

private theorem exact_nonlinear_roots_checked :
    exactNonlinearRoots.all (fun root => decide (root < 8130)) = true := by
  decide

theorem nonlinear_canonical : program.nonlinearExecutable.Canonical true := by
  unfold program ExpressionProgram.Canonical
  constructor
  · intro node expression found
    have checked := (checkIndexed_eq_true
      (SmzaRp04PackedAcceptanceData.expressionPredicate true)
      exactNonlinearExpressions 0).mp
        SmzaRp04PackedAcceptanceChecks.nonlinear_checked
    have decision := checked node expression found
    simpa only [Nat.zero_add, SmzaRp04PackedAcceptanceData.expressionPredicate,
      decide_eq_true_eq] using decision
  · intro root member
    rw [exact_nonlinear_expressions_length]
    have decision := (List.all_eq_true.mp exact_nonlinear_roots_checked) root member
    simpa only [decide_eq_true_eq] using decision

theorem csr_canonical :
    ({ expressions := exactCsrExpressions, roots := [] } : ExpressionProgram).Canonical false := by
  unfold ExpressionProgram.Canonical
  constructor
  · intro node expression found
    have checked := (checkIndexed_eq_true
      (SmzaRp04PackedAcceptanceData.expressionPredicate false)
      exactCsrExpressions 0).mp
        SmzaRp04PackedAcceptanceChecks.csrExpressions_checked
    have decision := checked node expression found
    simpa only [Nat.zero_add, SmzaRp04PackedAcceptanceData.expressionPredicate,
      decide_eq_true_eq] using decision
  · simp

theorem csr_canonical_with_rows :
    ({ expressions := exactCsrExpressions, roots := [] } : ExpressionProgram).Canonical true := by
  constructor
  · intro index expression found
    exact canonical_without_rows_allows_rows (csr_canonical.1 index expression found)
  · simp

theorem csr_coordinates : ∀ entry, entry ∈ exactCsrAttempts →
    (∀ term, term ∈ entry.terms → term.1 < 43904 ∧ term.2 < exactCsrExpressions.length) ∧
    entry.targetRoot < exactCsrExpressions.length := by
  have checked := SmzaRp04PackedAcceptanceChecks.csrAttempts_coordinates_checked
  have bounded : ∀ entry, entry ∈ exactCsrAttempts →
      (∀ term, term ∈ entry.terms → term.1 < 43904 ∧ term.2 < 564) ∧
      entry.targetRoot < 564 := by
    simpa only [List.all_eq_true,
      SmzaRp04PackedAcceptanceData.attemptCoordinatesPredicate,
      Bool.and_eq_true, decide_eq_true_eq] using checked
  simpa only [SmzaRp04PackedAcceptanceChecks.csrExpressions_length] using bounded

theorem exact_attempt_coordinates_bounded (entry : CsrExecutableAttempt)
    (member : entry ∈ exactCsrAttempts) : ∀ term, term ∈ entry.terms → term.1 < 43904 := by
  intro term inTerms
  exact ((csr_coordinates entry member).1 term inTerms).1

theorem csr_zero_node : exactCsrExpressions[0]? = some (.constant 0) := by decide
theorem csr_one_node : exactCsrExpressions[1]? = some (.constant 1) := by decide
theorem fallback_row : exactCsrAttempts[19295]? =
    some (attempt 19295 45 0 0 [(41528, 1)] 0) := by
  exact SmzaRp04PackedAcceptanceChecks.fallback_row

def publicExpressionValues (publicValues : List Nat) : List Nat :=
  (evalExpressionNodes publicValues [] exactCsrExpressions).getD []

theorem public_expression_values_of_success (publicValues values : List Nat)
    (evaluated : evalExpressionNodes publicValues [] exactCsrExpressions = some values) :
    publicExpressionValues publicValues = values := by
  simp only [publicExpressionValues, evaluated, Option.getD_some]

def rawCoefficient (publicValues : List Nat) (attempt : CsrExecutableAttempt) :
    PackedIndex → Goldilocks :=
  denseCoefficient (publicExpressionValues publicValues) attempt.terms

def rowTarget (publicValues : List Nat) (attempt : CsrExecutableAttempt) : Goldilocks :=
  (publicExpressionValues publicValues).getD attempt.targetRoot 0

def rowEmpty (publicValues : List Nat) (attempt : CsrExecutableAttempt) : Prop :=
  ∀ index, rawCoefficient publicValues attempt index = 0

def rowEmitted (publicValues : List Nat) (attempt : CsrExecutableAttempt) : Prop :=
  ¬ (rowEmpty publicValues attempt ∧ rowTarget publicValues attempt = 0)

/-- Source fallback for an impossible public-only row: tail_source_index(120). -/
def normalizedCoefficient (publicValues : List Nat) (attempt : CsrExecutableAttempt)
    (index : PackedIndex) : Goldilocks :=
  if rowEmpty publicValues attempt then
    if index.val = 41528 then 1 else 0
  else rawCoefficient publicValues attempt index

def retainedAttempts (publicValues : List Nat) : List CsrExecutableAttempt :=
  exactCsrAttempts.filter (fun attempt => decide (rowEmitted publicValues attempt))

theorem canonical_public_expression_program_succeeds (publicValues : List Nat)
    (canonical : CanonicalPublicWords publicValues) :
    evalExpressionNodes publicValues [] exactCsrExpressions =
      some (publicExpressionValues publicValues) := by
  obtain ⟨values, evaluated, _⟩ := canonical_expression_program_resolves publicValues []
    { expressions := exactCsrExpressions, roots := [] } false (Nat.le_of_eq canonical.1.symm) (by simp)
      csr_canonical
  rw [public_expression_values_of_success publicValues values evaluated]
  exact evaluated

def NormalizedRowsHold (publicValues witness : List Nat) : Prop :=
  ∀ index : Fin (retainedAttempts publicValues).length,
    (∑ coordinate : PackedIndex, normalizedCoefficient publicValues
      (retainedAttempts publicValues)[index.val] coordinate * packedFieldValues witness coordinate) =
      rowTarget publicValues (retainedAttempts publicValues)[index.val]

theorem normalized_equation_for_emitted (publicValues witness : List Nat)
    (equalities : NormalizedRowsHold publicValues witness)
    (entry : CsrExecutableAttempt) (member : entry ∈ exactCsrAttempts)
    (emitted : rowEmitted publicValues entry) :
    (∑ coordinate : PackedIndex, normalizedCoefficient publicValues entry coordinate *
      packedFieldValues witness coordinate) = rowTarget publicValues entry := by
  have retained : entry ∈ retainedAttempts publicValues := by
    simpa only [retainedAttempts, List.mem_filter, decide_eq_true_eq] using And.intro member emitted
  obtain ⟨index, bound, same⟩ := List.mem_iff_getElem.mp retained
  simpa only [same] using equalities ⟨index, bound⟩

theorem canonical_public_constant_values (publicValues : List Nat)
    (canonical : CanonicalPublicWords publicValues) :
    (publicExpressionValues publicValues).getD 0 0 = 0 ∧
      (publicExpressionValues publicValues).getD 1 0 = 1 := by
  have evaluated := canonical_public_expression_program_succeeds publicValues canonical
  have node0 := evaluated_program_satisfies_each_node csr_canonical_with_rows
    evaluated csr_zero_node
  have node1 := evaluated_program_satisfies_each_node csr_canonical_with_rows
    evaluated csr_one_node
  have zero : (publicExpressionValues publicValues)[0]? = some 0 := by
    simpa only [evalFieldExpression, fieldNormalize, Nat.zero_mod] using node0
  have one : (publicExpressionValues publicValues)[1]? = some 1 := by
    simpa only [evalFieldExpression, fieldNormalize, fieldModulus, Nat.reduceMod] using node1
  simp only [List.getD_eq_getElem?_getD, zero, one, Option.getD_some, and_self]

theorem fallback_coordinate_sum (witness : List Nat) :
    (∑ coordinate : PackedIndex, (if coordinate.val = 41528 then (1 : Goldilocks) else 0) *
      packedFieldValues witness coordinate) = packedFieldValues witness ⟨41528, by decide⟩ := by
  have selector (coordinate : PackedIndex) : coordinate.val = 41528 ↔
      coordinate = ⟨41528, by decide⟩ := by simp only [Fin.ext_iff]
  simp only [selector, ite_mul, one_mul, zero_mul, Finset.sum_ite_eq', Finset.mem_univ, if_true]

/-- The real singleton-one/zero-target CSR row forces the fallback coordinate
to zero without presupposing complete source acceptance. -/
theorem normalized_rows_force_fallback_zero (publicValues witness : List Nat)
    (canonical : CanonicalPublicWords publicValues)
    (equalities : NormalizedRowsHold publicValues witness) :
    packedFieldValues witness ⟨41528, by decide⟩ = 0 := by
  let entry := attempt 19295 45 0 0 [(41528, 1)] 0
  have member : entry ∈ exactCsrAttempts :=
    List.mem_of_getElem? fallback_row
  have constants := canonical_public_constant_values publicValues canonical
  have coefficient (coordinate : PackedIndex) : rawCoefficient publicValues entry coordinate =
      if coordinate.val = 41528 then (1 : Goldilocks) else 0 := by
    simp only [rawCoefficient, denseCoefficient, entry, attempt, List.map_cons,
      List.map_nil, List.sum_cons, List.sum_nil, add_zero, constants.2, Nat.cast_one, eq_comm]
  have target : rowTarget publicValues entry = 0 := by
    simp only [rowTarget, entry, attempt, constants.1, Nat.cast_zero]
  have nonempty : ¬ rowEmpty publicValues entry := by
    intro empty
    have impossible := empty ⟨41528, by decide⟩
    rw [coefficient] at impossible
    simp only [if_true] at impossible
    exact one_ne_zero impossible
  have emitted : rowEmitted publicValues entry := fun absent => nonempty absent.1
  have equation := normalized_equation_for_emitted publicValues witness equalities entry member emitted
  simp only [normalizedCoefficient, if_neg nonempty, coefficient, target] at equation
  rw [fallback_coordinate_sum] at equation
  exact equation

/-- Impossible-empty normalization cannot hide an unsatisfied raw CSR row:
the very same source system independently forces its fallback coordinate zero. -/
theorem normalized_rows_supply_all_raw_equations (publicValues witness : List Nat)
    (canonical : CanonicalPublicWords publicValues)
    (equalities : NormalizedRowsHold publicValues witness)
    (entry : CsrExecutableAttempt) (member : entry ∈ exactCsrAttempts) :
    (∑ coordinate : PackedIndex, rawCoefficient publicValues entry coordinate *
      packedFieldValues witness coordinate) = rowTarget publicValues entry := by
  by_cases emitted : rowEmitted publicValues entry
  · have equation := normalized_equation_for_emitted publicValues witness equalities entry member emitted
    by_cases empty : rowEmpty publicValues entry
    · have zero := normalized_rows_force_fallback_zero publicValues witness canonical equalities
      simp only [normalizedCoefficient, if_pos empty] at equation
      rw [fallback_coordinate_sum, zero] at equation
      exact False.elim (emitted ⟨empty, equation.symm⟩)
    · simpa only [normalizedCoefficient, if_neg empty] using equation
  · have absent : rowEmpty publicValues entry ∧ rowTarget publicValues entry = 0 :=
      Classical.not_not.mp emitted
    rw [absent.2]
    apply Finset.sum_eq_zero
    intro coordinate _
    rw [absent.1 coordinate, zero_mul]

theorem normalized_rows_supply_csr_source_acceptance (publicValues witness : List Nat)
    (publicCanonical : CanonicalPublicWords publicValues)
    (witnessCanonical : CanonicalPackedWitness witness)
    (equalities : NormalizedRowsHold publicValues witness) :
    csrExecutableProgramAccepts exactCsrExpressions exactCsrAttempts publicValues witness := by
  have evaluated := canonical_public_expression_program_succeeds publicValues publicCanonical
  have valuesCanonical := source_go_canonical publicValues [] [] (publicExpressionValues publicValues)
    exactCsrExpressions (by simp) evaluated
  obtain ⟨_, succeeds, length⟩ := canonical_expression_program_resolves publicValues []
    { expressions := exactCsrExpressions, roots := [] } false
      (Nat.le_of_eq publicCanonical.1.symm) (by simp) csr_canonical
  have valuesLength : (publicExpressionValues publicValues).length = exactCsrExpressions.length := by
    rw [evaluated] at succeeds
    simpa only [Option.some.inj succeeds] using length
  refine ⟨publicExpressionValues publicValues, evaluated, ?_⟩
  intro entry member
  obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp member
  have canonical := csr_coordinates entry member
  have coordinates := canonical.1
  change ∀ term, term ∈ entry.terms → term.1 < packedWitnessWordCount ∧
    term.2 < exactCsrExpressions.length at coordinates
  apply field_csr_equation_supplies_source_acceptance _ _ entry
  · intro term inTerms
    simpa only [witnessCanonical.1, valuesLength] using coordinates term inTerms
  · have target : entry.targetRoot < exactCsrExpressions.length := canonical.2
    simpa only [valuesLength] using target
  · exact valuesCanonical
  · have raw := normalized_rows_supply_all_raw_equations publicValues witness publicCanonical
      equalities entry member
    simpa only [rawCoefficient, rowTarget,
      dense_coefficient_dot _ witness entry.terms (exact_attempt_coordinates_bounded entry member)] using raw


/-- The actual repaired packed interpreter follows from its own normalized
CSR equalities and its own executable nonlinear field roots. These are the
unbatched facts a repaired PIOP candidate must supply; no evaluator-success
or packed-program acceptance premise occurs. -/
theorem actual_repaired_fields_supply_packed_acceptance
    (publicValues witness : List Nat)
    (publicCanonical : CanonicalPublicWords publicValues)
    (witnessCanonical : CanonicalPackedWitness witness)
    (linear : NormalizedRowsHold publicValues witness)
    (nonlinear : ∀ lane : Fin 64, ∀ root, root ∈ exactNonlinearRoots →
      fieldAt exactNonlinearExpressions (fun n => (publicValues.getD n 0 : Goldilocks))
        (fun n => ((packedWitnessLaneRows witness lane.val).getD n 0 : Goldilocks)) root = 0) :
    program.AcceptsPacked publicValues witness := by
  refine ⟨publicCanonical, witnessCanonical, ?_, ?_⟩
  · intro lane laneBound
    apply field_roots_zero_supplies_source_acceptance publicValues
      (packedWitnessLaneRows witness lane) program.nonlinearExecutable
      (Nat.le_of_eq publicCanonical.1.symm)
    · rw [packed_witness_lane_rows_have_exact_relation_length]
      exact Nat.le_refl _
    · exact nonlinear_canonical
    · exact nonlinear ⟨lane, laneBound⟩
  · exact normalized_rows_supply_csr_source_acceptance publicValues witness
      publicCanonical witnessCanonical linear

end
end HegemonCrypto.SmallWood.SmzaRp04PackedAcceptance
