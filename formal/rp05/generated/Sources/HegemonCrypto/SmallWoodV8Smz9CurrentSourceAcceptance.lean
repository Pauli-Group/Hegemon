import HegemonCrypto.SmallWoodV8Smz9DecodedPolynomialSource

/-!
# Total source interpreters and normalized relation acceptance

The finite source evaluators retain their Option failure paths. Canonical
program coordinates and exact input lengths discharge those paths; field
equalities are then lifted to canonical natural representatives.
-/

namespace HegemonCrypto.SmallWood.V8Smz9CurrentSourceAcceptance

open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9ProgramPolynomials V8Smz9SemanticBinding V8Smz9SemanticDenseRange
open V8Smz9CurrentPublicContext V8Smz9DecodedPolynomialSource
open V8Smz9RelationProgramComponentsGenerated V8Smz9ProgramCanonicalityGenerated
open V8Smz9ProgramCanonicality
open scoped BigOperators Classical

noncomputable section
set_option maxRecDepth 10000
set_option maxHeartbeats 1500000
set_option backward.isDefEq.respectTransparency false

theorem bounded_lookup_resolves {values : List Nat} {index : Nat}
    (bound : index < values.length) : ∃ value, values[index]? = some value :=
  ⟨values[index], List.getElem?_eq_getElem bound⟩

theorem canonical_expression_resolves (publicValues rows values : List Nat)
    (allowRows : Bool) (expression : FieldExpression)
    (publicLength : publicStatementWordCount ≤ publicValues.length)
    (rowLength : allowRows = true → 686 ≤ rows.length)
    (canonical : expression.CanonicalAt allowRows values.length) :
    ∃ value, evalFieldExpression publicValues rows values expression = some value := by
  cases expression with
  | constant value => exact ⟨fieldNormalize value, rfl⟩
  | publicWord index =>
      obtain ⟨value, found⟩ := bounded_lookup_resolves (canonical.trans_le publicLength)
      exact ⟨fieldNormalize value, by simp only [evalFieldExpression, found, Option.map_some]⟩
  | witnessRow index =>
      obtain ⟨value, found⟩ := bounded_lookup_resolves (canonical.2.trans_le (rowLength canonical.1))
      exact ⟨fieldNormalize value, by simp only [evalFieldExpression, found, Option.map_some]⟩
  | add left right =>
      obtain ⟨leftValue, leftFound⟩ := bounded_lookup_resolves canonical.1
      obtain ⟨rightValue, rightFound⟩ := bounded_lookup_resolves canonical.2
      exact ⟨fieldAdd leftValue rightValue, by simp [evalFieldExpression, leftFound, rightFound]⟩
  | sub left right =>
      obtain ⟨leftValue, leftFound⟩ := bounded_lookup_resolves canonical.1
      obtain ⟨rightValue, rightFound⟩ := bounded_lookup_resolves canonical.2
      exact ⟨fieldSub leftValue rightValue, by simp [evalFieldExpression, leftFound, rightFound]⟩
  | mul left right =>
      obtain ⟨leftValue, leftFound⟩ := bounded_lookup_resolves canonical.1
      obtain ⟨rightValue, rightFound⟩ := bounded_lookup_resolves canonical.2
      exact ⟨fieldMul leftValue rightValue, by simp [evalFieldExpression, leftFound, rightFound]⟩
  | neg index =>
      obtain ⟨value, found⟩ := bounded_lookup_resolves canonical
      exact ⟨fieldSub 0 value, by simp [evalFieldExpression, found]⟩
  | inverse index =>
      obtain ⟨value, found⟩ := bounded_lookup_resolves canonical
      exact ⟨fieldInverse value, by simp [evalFieldExpression, found]⟩
  | selectEqual left right equal notEqual =>
      obtain ⟨leftValue, leftFound⟩ := bounded_lookup_resolves canonical.1
      obtain ⟨rightValue, rightFound⟩ := bounded_lookup_resolves canonical.2.1
      obtain ⟨equalValue, equalFound⟩ := bounded_lookup_resolves canonical.2.2.1
      obtain ⟨notEqualValue, notEqualFound⟩ := bounded_lookup_resolves canonical.2.2.2
      refine ⟨if leftValue = rightValue then equalValue else notEqualValue, ?_⟩
      split_ifs <;> simp_all [evalFieldExpression]
  | bit index bitIndex =>
      obtain ⟨value, found⟩ := bounded_lookup_resolves canonical.1
      exact ⟨(value / 2 ^ bitIndex) % 2, by simp [evalFieldExpression, found]⟩

theorem canonical_expression_program_go_resolves (publicValues rows : List Nat)
    (allowRows : Bool) (publicLength : publicStatementWordCount ≤ publicValues.length)
    (rowLength : allowRows = true → 686 ≤ rows.length)
    (remaining : List FieldExpression) (values : List Nat)
    (canonical : ∀ (index : Nat) (expression : FieldExpression), remaining[index]? = some expression →
      expression.CanonicalAt allowRows (values.length + index)) :
    ∃ result, evalExpressionNodes.go publicValues rows remaining values = some result ∧
      result.length = values.length + remaining.length := by
  induction remaining generalizing values with
  | nil => exact ⟨values, rfl, by simp⟩
  | cons expression tail ih =>
      have first : expression.CanonicalAt allowRows values.length := by
        simpa only [Nat.add_zero] using canonical 0 expression (by rfl)
      obtain ⟨value, evaluated⟩ := canonical_expression_resolves publicValues rows values
        allowRows expression publicLength rowLength first
      have rest : ∀ (index : Nat) (next : FieldExpression), tail[index]? = some next →
          next.CanonicalAt allowRows ((values ++ [value]).length + index) := by
        intro index next found
        have checked := canonical (index + 1) next (by simpa using found)
        simpa only [List.length_append, List.length_singleton, Nat.add_assoc, Nat.add_comm index 1] using checked
      obtain ⟨result, succeeds, length⟩ := ih (values ++ [value]) rest
      refine ⟨result, ?_, ?_⟩
      · simp [evalExpressionNodes.go, evaluated, succeeds]
      · simpa only [List.length_append, List.length_singleton, List.length_cons,
          List.length_nil, Nat.zero_add, Nat.add_assoc, Nat.add_comm 1 tail.length] using length

theorem canonical_expression_program_resolves (publicValues rows : List Nat)
    (program : ExpressionProgram) (allowRows : Bool)
    (publicLength : publicStatementWordCount ≤ publicValues.length)
    (rowLength : allowRows = true → 686 ≤ rows.length)
    (canonical : program.Canonical allowRows) :
    ∃ values, evalExpressionNodes publicValues rows program.expressions = some values ∧
      values.length = program.expressions.length := by
  simpa only [evalExpressionNodes, List.length_nil, Nat.zero_add] using
    canonical_expression_program_go_resolves publicValues rows allowRows publicLength rowLength
      program.expressions [] (by simpa using canonical.1)

theorem canonical_public_expression_program_succeeds (publicValues : List Nat)
    (canonical : CanonicalPublicWords publicValues) :
    evalExpressionNodes publicValues [] exactCsrExpressions =
      some (publicExpressionValues publicValues) := by
  obtain ⟨values, evaluated, _⟩ := canonical_expression_program_resolves publicValues []
    { expressions := exactCsrExpressions, roots := [] } false (Nat.le_of_eq canonical.1.symm) (by simp)
      hgv8rp03_csr_expression_program_is_canonical
  rw [public_expression_values_of_success publicValues values evaluated]
  exact evaluated

theorem bounded_csr_terms_resolve (values witness : List Nat) (terms : List (Nat × Nat))
    (bounded : ∀ term, term ∈ terms → term.1 < witness.length ∧ term.2 < values.length) :
    ∃ result, evalCsrTerms values witness terms = some result ∧ result < fieldModulus := by
  induction terms with
  | nil => exact ⟨0, rfl, by decide⟩
  | cons term tail ih =>
      have this := bounded term (by simp)
      obtain ⟨coefficient, coefficientFound⟩ := bounded_lookup_resolves this.2
      obtain ⟨value, valueFound⟩ := bounded_lookup_resolves this.1
      obtain ⟨rest, evaluated, _⟩ := ih (fun term member => bounded term (by simp [member]))
      refine ⟨fieldAdd (fieldMul coefficient value) rest, ?_, normalize_bound _⟩
      simp [evalCsrTerms, coefficientFound, valueFound, evaluated]

theorem field_csr_equation_supplies_source_acceptance
    (values witness : List Nat) (entry : CsrExecutableAttempt)
    (coordinates : ∀ term, term ∈ entry.terms →
      term.1 < witness.length ∧ term.2 < values.length)
    (targetBound : entry.targetRoot < values.length)
    (valuesCanonical : ∀ value, value ∈ values → value < fieldModulus)
    (equal : csrFieldSum values witness entry.terms =
      (values.getD entry.targetRoot 0 : Goldilocks)) :
    entry.Accepts values witness := by
  obtain ⟨result, evaluated, resultBound⟩ := bounded_csr_terms_resolve values witness entry.terms coordinates
  have targetFound := List.getElem?_eq_getElem targetBound
  have targetCanonical := valuesCanonical values[entry.targetRoot] (List.getElem_mem targetBound)
  refine ⟨result, values[entry.targetRoot], evaluated, targetFound, ?_⟩
  apply canonical_nat_cast_injective resultBound targetCanonical
  rw [eval_csr_terms_field_sum evaluated, equal]
  simp only [List.getD_eq_getElem?_getD, targetFound, Option.getD_some]

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
  have node0 := evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    evaluated exact_transparent_balance_expression_nodes.1
  have node1 := evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows
    evaluated exact_csr_one_expression_node
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
  let entry := attempt 19298 39 0 0 [(41528, 1)] 0
  have member : entry ∈ exactCsrAttempts :=
    List.mem_of_getElem? exact_transparent_balance_attempts.2.2
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
      (Nat.le_of_eq publicCanonical.1.symm) (by simp) hgv8rp03_csr_expression_program_is_canonical
  have valuesLength : (publicExpressionValues publicValues).length = exactCsrExpressions.length := by
    rw [evaluated] at succeeds
    simpa only [Option.some.inj succeeds] using length
  refine ⟨publicExpressionValues publicValues, evaluated, ?_⟩
  intro entry member
  obtain ⟨index, found⟩ := List.mem_iff_getElem?.mp member
  have canonical := hgv8rp03_program_is_canonical.2.2.2.2.2.2.2.2.2.2.2.1 index entry found
  have coordinates := canonical.1.2.2.2.1
  change ∀ term, term ∈ entry.terms → term.1 < packedWitnessWordCount ∧
    term.2 < exactCsrExpressions.length at coordinates
  apply field_csr_equation_supplies_source_acceptance _ _ entry
  · intro term inTerms
    simpa only [witnessCanonical.1, valuesLength] using coordinates term inTerms
  · have target : entry.targetRoot < exactCsrExpressions.length := canonical.1.2.2.2.2
    simpa only [valuesLength] using target
  · exact valuesCanonical
  · have raw := normalized_rows_supply_all_raw_equations publicValues witness publicCanonical
      equalities entry member
    simpa only [rawCoefficient, rowTarget,
      dense_coefficient_dot _ witness entry.terms (exact_attempt_coordinates_bounded entry member)] using raw

theorem field_roots_zero_supplies_source_acceptance
    (publicValues rows : List Nat) (program : ExpressionProgram)
    (publicLength : publicStatementWordCount ≤ publicValues.length)
    (rowLength : 686 ≤ rows.length) (canonical : program.Canonical true)
    (zero : ∀ root, root ∈ program.roots →
      fieldAt program.expressions (fun n => (publicValues.getD n 0 : Goldilocks))
        (fun n => (rows.getD n 0 : Goldilocks)) root = 0) :
    program.Accepts publicValues rows := by
  obtain ⟨values, evaluated, valuesLength⟩ := canonical_expression_program_resolves
    publicValues rows program true publicLength (fun _ => rowLength) canonical
  have valuesCanonical := source_go_canonical publicValues rows [] values program.expressions
    (by simp) evaluated
  refine ⟨values, evaluated, ?_⟩
  have rootZero : ∀ root, root ∈ program.roots → values[root]? = some 0 := by
    intro root member
    have rootBound := canonical.2 root member
    have valueBound : root < values.length := by omega
    have fieldEqual := fieldAt_refines_source program publicValues rows values canonical evaluated root rootBound
    rw [zero root member] at fieldEqual
    have found := List.getElem?_eq_getElem valueBound
    have natZero : values[root] = 0 := by
      apply canonical_nat_cast_injective
        (valuesCanonical _ (List.getElem_mem valueBound)) (by decide)
      simpa only [List.getD_eq_getElem?_getD, found, Option.getD_some, Nat.cast_zero] using fieldEqual.symm
    simpa only [natZero] using found
  calc
    program.roots.map (fun root => values[root]?) = program.roots.map (fun _ => some 0) := by
      apply List.map_congr_left
      exact rootZero
    _ = (List.replicate program.roots.length 0).map some := by simp

theorem source_packing_rows_field_values
    (values : V8Smz9EagerPrivacy.WitnessPackingValues Goldilocks) (lane : Fin 64) :
    V8Smz9EagerSimulator.openedWitnessAtNat (fun row => values row lane) =
      (fun row => ((V8Smz9CurrentProgramOpeningBinding.sourcePackingRows values lane).getD row 0 : Goldilocks)) := by
  have atIndex (row : Fin 686) :
      ((V8Smz9CurrentProgramOpeningBinding.sourcePackingRows values lane).getD row.val 0 : Goldilocks) =
      values row lane := by
    simp only [V8Smz9CurrentProgramOpeningBinding.sourcePackingRows, List.getD_eq_getElem?_getD,
      List.getElem?_ofFn, Fin.isLt, ↓reduceDIte, Option.getD_some, ZMod.natCast_zmod_val]
  funext row
  by_cases bounded : row < 686
  · rw [V8Smz9EagerSimulator.openedWitnessAtNat, dif_pos bounded]
    exact (atIndex ⟨row, bounded⟩).symm
  · have noValue : (V8Smz9CurrentProgramOpeningBinding.sourcePackingRows values lane)[row]? = none := by
      apply List.getElem?_eq_none
      simpa only [V8Smz9CurrentProgramOpeningBinding.sourcePackingRows, List.length_ofFn] using
        Nat.le_of_not_gt bounded
    simp only [V8Smz9EagerSimulator.openedWitnessAtNat, dif_neg bounded,
      List.getD_eq_getElem?_getD, noValue, Option.getD_none, Nat.cast_zero]

theorem source_openings_zero_supplies_nonlinear_acceptance
    (publicValues witness : List Nat) (publicCanonical : CanonicalPublicWords publicValues)
    (witnessCanonical : CanonicalPackedWitness witness)
    (zero : ∀ root lane, V8Smz9CurrentProgramPiop.currentConstraintOpenings
      (publicParameters publicValues 0) (fun row => packingValues witness row lane) root = 0)
    (lane : Fin 64) :
    hgv8rp03ProgramComponents.nonlinearExecutable.Accepts publicValues
      (packedWitnessLaneRows witness lane.val) := by
  rw [← source_packing_rows_match_packed_lane witnessCanonical lane]
  apply field_roots_zero_supplies_source_acceptance
  · exact Nat.le_of_eq publicCanonical.1.symm
  · simp only [V8Smz9CurrentProgramOpeningBinding.sourcePackingRows, List.length_ofFn, le_refl]
  · exact hgv8rp03_nonlinear_expression_program_is_canonical
  · intro root member
    change root ∈ exactNonlinearRoots at member
    obtain ⟨index, bound, same⟩ := List.mem_iff_getElem.mp member
    have indexBound : index < 830 := by simpa only [exact_root_count] using bound
    have rootIndex : exactNonlinearRoots.getD index 0 = root := by
      simp only [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem bound, Option.getD_some, same]
    have vanishes := zero ⟨index, indexBound⟩ lane
    change fieldAt exactNonlinearExpressions (fun n => (publicValues.getD n 0 : Goldilocks))
      (V8Smz9EagerSimulator.openedWitnessAtNat (fun row => packingValues witness row lane))
      (exactNonlinearRoots.getD index 0) = 0 at vanishes
    rw [source_packing_rows_field_values, rootIndex] at vanishes
    exact vanishes

theorem decoded_source_relation_supplies_normalized_rows (publicValues : List Nat)
    (source : SourcePolynomials) (relation : DecodedSourceRelation publicValues source) :
    NormalizedRowsHold publicValues (packedWitness source) := by
  intro index
  have equation := relation.2 index
  change (∑ row : Fin 686, ∑ lane : Fin 64,
    normalizedCoefficient publicValues (retainedAttempts publicValues)[index.val]
      (finProdFinEquiv (row, lane)) *
        packedFieldValues (packedWitness source) (finProdFinEquiv (row, lane))) = _ at equation
  have reindex (f : PackedIndex → Goldilocks) :
      (∑ row : Fin 686, ∑ lane : Fin 64, f (finProdFinEquiv (row, lane))) = ∑ coordinate, f coordinate := by
    calc
      _ = ∑ pair : Fin 686 × Fin 64, f (finProdFinEquiv pair) :=
        (Fintype.sum_prod_type _).symm
      _ = _ := Equiv.sum_comp (finProdFinEquiv : Fin 686 × Fin 64 ≃ PackedIndex) f
  rw [reindex (fun coordinate => normalizedCoefficient publicValues
    (retainedAttempts publicValues)[index.val] coordinate *
      packedFieldValues (packedWitness source) coordinate)] at equation
  exact equation

/-- Complete unchanged raw packed interpreter acceptance, derived from the
generated decoded source relation. No evaluator-success or decoded validity
receipt is supplied. Public admission remains the explicit frontend boundary. -/
theorem decoded_source_relation_supplies_packed_acceptance (publicValues : List Nat)
    (source : SourcePolynomials) (publicCanonical : CanonicalPublicWords publicValues)
    (relation : DecodedSourceRelation publicValues source) :
    hgv8rp03ProgramComponents.AcceptsPacked publicValues (packedWitness source) := by
  refine ⟨publicCanonical, packed_witness_canonical source, ?_, ?_⟩
  · intro lane bound
    exact source_openings_zero_supplies_nonlinear_acceptance publicValues (packedWitness source)
      publicCanonical (packed_witness_canonical source) relation.1 ⟨lane, bound⟩
  · exact normalized_rows_supply_csr_source_acceptance publicValues (packedWitness source)
      publicCanonical (packed_witness_canonical source)
      (decoded_source_relation_supplies_normalized_rows publicValues source relation)

theorem fully_satisfied_decoded_candidate_supplies_packed_acceptance
    (publicValues : List Nat) (source : SourcePolynomials)
    (publicCanonical : CanonicalPublicWords publicValues)
    (satisfied : PiopExtraction.FullySatisfied (sourcePiopCandidate publicValues source).system) :
    hgv8rp03ProgramComponents.AcceptsPacked publicValues (packedWitness source) :=
  decoded_source_relation_supplies_packed_acceptance publicValues source publicCanonical
    (fully_satisfied_candidate_supplies_decoded_source_relation publicValues source satisfied)

end
end HegemonCrypto.SmallWood.V8Smz9CurrentSourceAcceptance
