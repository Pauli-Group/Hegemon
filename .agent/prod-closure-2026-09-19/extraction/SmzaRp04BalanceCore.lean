import SmzaRp04ActualProgram
import SmzaRp04PackedAcceptanceData
import HegemonCrypto.SmallWoodV8Smz9SemanticBalance
import HegemonCrypto.SmallWoodV8Smz9SourceDenseRoots

/-!
RP04-specific balance semantics.

The legacy semantic decoder names the RP03 note calls `1,37,73,76`.  RP04
inserted two call roles and its checked CSR table binds the four note sources at
`1,38,75,78`.  Consequently this file defines an RP04 projection instead of
reusing the RP03 `projectTypedWitness` theorem.

The nonlinear balance, asset-membership, and dense-range roots lie in the
unchanged prefix below node 1244.  Their formulas are transported through an
explicit prefix equality.  The linear note bindings and dense reconstruction
are proved separately from the actual RP04 CSR chunks and RP04 expression
nodes.  In particular, neither RP03 packed acceptance nor an assumed semantic
refinement proposition occurs in the endpoint.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04BalanceCore

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open V8Smz9ProgramPolynomials
  (fieldAt fieldAt_eq expressionField fieldAt_refines_source canonical_getD)
open V8Smz9SemanticBinding
  (evaluated_program_satisfies_each_node)
open V8Smz9SemanticDenseRange
  (F canonical_nat_cast_injective field_sub_cast csrFieldSum
    accepted_csr_attempt_field_equality denseDigitAddress denseTopAddress
    densePrivateAddress denseNaturalValue dense_natural_reconstruction_bound
    canonical_public_coordinate canonical_packed_coordinate)
open V8Smz9SemanticDecoder
  (packedWord packed_word_canonical spongeSourceWord projectNote projectSelectors)
open V8Smz9SemanticAssetMembership
  (assetRootAt asset_root_at_valid actual_asset_root_formula four_asset_factors_zero
    actual_node_field_equation admitted_public_lengths encoded_balance_asset admitted_input_flag_one
    admitted_output_flag_one)
open V8Smz9SemanticBalance
  (sourceWeight sourceContribution sourceDelta sourceExpected signedFieldValue
    balanceRootSourceAt balance_root_source_at_valid actual_balance_root_formula
    actual_expected_common_terms actual_source_public
    actual_source_constants interpolationTriple_eq_numerator
    sourceWeight_eq_interpolationWeight typedExpectedField
    encoded_balance_scalar encoded_compatibility_scalar pair_sum_extra_canonical
    valueRow value_row_source)
open V8Smz9SemanticInterpolation
  (NonpaddingDistinct interpolationWeight_eq_indicator)
open SmzaRp04Components
open scoped BigOperators Classical

noncomputable section
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

/-! ## The actual RP04 typed projection used by the ledger -/

def noteCall (note : Nat) : Nat := [1, 38, 75, 78].getD note 0

def projectInput (statement : V8PublicStatement) (packed : List Nat)
    (input : Nat) : V8InputWitness :=
  let active := flagAt statement.inputFlags input
  let note := projectNote packed (noteCall input)
  { V8Smz9SemanticDecoder.projectInput statement packed input with
    note := note
    balanceSelectors := projectSelectors active note.assetId statement }

def projectOutput (statement : V8PublicStatement) (packed : List Nat)
    (output : Nat) : V8OutputWitness :=
  let active := flagAt statement.outputFlags output
  let note := projectNote packed (noteCall (2 + output))
  { V8Smz9SemanticDecoder.projectOutput statement packed output with
    note := note
    balanceSelectors := projectSelectors active note.assetId statement }

def projectTypedWitness (statement : V8PublicStatement) (packed : List Nat) : V8Witness :=
  { V8Smz9SemanticDecoder.projectTypedWitness statement packed with
    inputs := (List.range 2).map (projectInput statement packed)
    outputs := (List.range 2).map (projectOutput statement packed) }

def CanonicalPublicPackedDomain (statement : V8PublicStatement)
    (publicWords packed : List Nat) : Prop :=
  encodePublicStatement statement = publicWords ∧
    CanonicalPublicStatement exactV8SemanticPrimitives statement ∧
    program.AcceptsPacked publicWords packed

/-! ## Exact nonlinear-prefix transport -/

private theorem fieldAt_eq_of_prefix
    (left right : List FieldExpression) (pub rows : Nat → F) (node : Nat)
    (same : ∀ index, index ≤ node → left[index]? = right[index]?) :
    fieldAt left pub rows node = fieldAt right pub rows node := by
  induction node using Nat.strong_induction_on with
  | h node ih =>
      rw [fieldAt_eq, fieldAt_eq, same node (Nat.le_refl node)]
      cases found : right[node]? with
      | none => rfl
      | some expression =>
          simp only
          apply congrArg
            (fun values : Nat → F => expressionField pub rows values expression)
          funext index
          by_cases prior : index < node
          · simp only [if_pos prior]
            apply ih index prior
            intro earlier earlierBound
            exact same earlier (earlierBound.trans (Nat.le_of_lt prior))
          · simp only [if_neg prior]

theorem nonlinear_prefix_eq :
    SmzaRp04Components.exactNonlinearExpressions.take 1244 =
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions.take 1244 := by
  rfl

private theorem nonlinear_getElem_eq {node : Nat} (bound : node < 1244) :
    SmzaRp04Components.exactNonlinearExpressions[node]? =
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions[node]? := by
  have same := congrArg (fun expressions : List FieldExpression => expressions[node]?)
    nonlinear_prefix_eq
  simpa only [List.getElem?_take, if_pos bound] using same

theorem fieldAt_rp04_eq_rp03 (pub rows : Nat → F) {node : Nat} (bound : node < 1244) :
    fieldAt SmzaRp04Components.exactNonlinearExpressions pub rows node =
      fieldAt V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows node := by
  apply fieldAt_eq_of_prefix
  intro index indexBound
  exact nonlinear_getElem_eq (by omega)

theorem accepted_source_root_zero_at_lane {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {lane : Nat} (laneBound : lane < 64)
    {root : Nat} (member : root ∈ SmzaRp04Components.exactNonlinearRoots) :
    fieldAt SmzaRp04Components.exactNonlinearExpressions
      (fun index => (publicWords.getD index 0 : F))
      (fun row => ((packedWitnessLaneRows packed lane).getD row 0 : F)) root = 0 := by
  obtain ⟨values, evaluated, zero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 lane laneBound) member
  have source := fieldAt_refines_source program.nonlinearExecutable publicWords
    (packedWitnessLaneRows packed lane) values
    SmzaRp04PackedAcceptance.nonlinear_canonical evaluated root
    (SmzaRp04PackedAcceptance.nonlinear_canonical.2 _ member)
  change fieldAt SmzaRp04Components.exactNonlinearExpressions _ _ root =
    (values.getD root 0 : F) at source
  rw [source]
  simp only [List.getD_eq_getElem?_getD, zero, Option.getD_some, Nat.cast_zero]

theorem accepted_source_root_zero {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {root : Nat} (member : root ∈ SmzaRp04Components.exactNonlinearRoots) :
    fieldAt SmzaRp04Components.exactNonlinearExpressions
      (fun index => (publicWords.getD index 0 : F))
      (fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)) root = 0 :=
  accepted_source_root_zero_at_lane accepted (by decide) member

private theorem enabled_root_member : 835 ∈ SmzaRp04Components.exactNonlinearRoots := by
  decide

private theorem balance_root_member {slot : Nat} (bound : slot < 4) :
    (balanceRootSourceAt slot).root ∈ SmzaRp04Components.exactNonlinearRoots := by
  interval_cases slot <;> decide

theorem accepted_source_enabled {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) :
    fieldAt V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions
      (fun index => (publicWords.getD index 0 : F))
      (fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)) 832 =
        (publicWords.getD 58 0 : F) := by
  let pub := fun index => (publicWords.getD index 0 : F)
  let rows := fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)
  have actualZero := accepted_source_root_zero accepted enabled_root_member
  have rootZero : fieldAt
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows 835 = 0 :=
    (fieldAt_rp04_eq_rp03 pub rows (node := 835) (by decide)).symm.trans actualZero
  have root := actual_node_field_equation pub rows
    (node := 835) (expression := .sub 62 832) (by decide)
  have flag := actual_source_public pub rows (index := 58) (by decide)
  simp only [expressionField, flag] at root
  have equal : pub 58 - fieldAt
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows 832 = 0 :=
    root.symm.trans rootZero
  simpa only [pub, rows] using (sub_eq_zero.mp equal).symm

/-- RP04 acceptance forces the four statement-level field balance equations. -/
theorem accepted_source_balance_equation {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    sourceDelta (fun index => (publicWords.getD index 0 : F))
      (fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)) slot =
      sourceExpected (fun index => (publicWords.getD index 0 : F)) slot := by
  let pub := fun index => (publicWords.getD index 0 : F)
  let rows := fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)
  have entry := balance_root_source_at_valid bound
  have actualZero := accepted_source_root_zero accepted (balance_root_member bound)
  have rootZero : fieldAt
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows
        (balanceRootSourceAt slot).root = 0 :=
    (fieldAt_rp04_eq_rp03 pub rows
      (node := (balanceRootSourceAt slot).root) (by interval_cases slot <;> decide)).symm.trans
        actualZero
  have formula := actual_balance_root_formula (balanceRootSourceAt slot) entry.1 pub rows
  rw [entry.2.1] at formula
  have delta := sub_eq_zero.mp (formula.symm.trans rootZero)
  have expected : fieldAt
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows
        (balanceRootSourceAt slot).expected = sourceExpected pub slot := by
    have common := actual_expected_common_terms pub rows
    by_cases native : slot = 0
    · have target := entry.2.2
      rw [if_pos native] at target
      simpa only [sourceExpected, if_pos native, target] using common.1
    · have target := entry.2.2
      rw [if_neg native] at target
      have selected := actual_node_field_equation pub rows target
      have asset : fieldAt
          V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows
            (58 + slot) = pub (54 + slot) := by
        simpa only [← Nat.add_assoc, Nat.reduceAdd] using
          actual_source_public pub rows (index := 54 + slot) (by omega)
      have stableAsset := actual_source_public pub rows (index := 59) (by decide)
      have enabled : fieldAt
          V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows 832 =
            pub 58 := accepted_source_enabled accepted
      have constants := actual_source_constants pub rows
      simpa only [expressionField, sourceExpected, if_neg native, asset, stableAsset,
        common.2, enabled, constants.1] using selected
  exact delta.trans expected

/-! ## RP04 CSR facts for the actual note calls -/

private theorem csr_chunks_flatten :
    SmzaRp04PackedAcceptanceData.csrAttemptChunks.flatten =
      SmzaRp04Components.exactCsrAttempts := by
  unfold SmzaRp04Components.exactCsrAttempts
  apply congrArg List.flatten
  rfl

private theorem chunk_entry_mem_exact {chunk : List CsrExecutableAttempt}
    {entry : CsrExecutableAttempt}
    (chunkMem : chunk ∈ SmzaRp04PackedAcceptanceData.csrAttemptChunks)
    (entryMem : entry ∈ chunk) : entry ∈ SmzaRp04Components.exactCsrAttempts := by
  rw [← csr_chunks_flatten]
  exact List.mem_flatten_of_mem chunkMem entryMem

private theorem chunk12_entry_mem_exact {chunk : List CsrExecutableAttempt}
    {entry : CsrExecutableAttempt}
    (chunkMem : chunk ∈ SmzaRp04PackedAcceptanceData.csrAttemptChunks12)
    (entryMem : entry ∈ chunk) : entry ∈ SmzaRp04Components.exactCsrAttempts := by
  apply chunk_entry_mem_exact
  · simp only [SmzaRp04PackedAcceptanceData.csrAttemptChunks, List.mem_append]
    aesop
  · exact entryMem

private theorem chunk14_entry_mem_exact {chunk : List CsrExecutableAttempt}
    {entry : CsrExecutableAttempt}
    (chunkMem : chunk ∈ SmzaRp04PackedAcceptanceData.csrAttemptChunks14)
    (entryMem : entry ∈ chunk) : entry ∈ SmzaRp04Components.exactCsrAttempts := by
  apply chunk_entry_mem_exact
  · simp only [SmzaRp04PackedAcceptanceData.csrAttemptChunks, List.mem_append]
    aesop
  · exact entryMem

def noteBridgeAttemptIndex (note : Nat) : Nat := [15775, 15814, 18353, 18392].getD note 0
def noteBridgeFamily (note : Nat) : Nat := if note < 2 then 14 else 23
def noteBridgeLocalIndex (note word : Nat) : Nat := 39 * (note % 2) + word

def noteBridgeExpectedAttempt (note word : Nat) : CsrExecutableAttempt :=
  SmzaRp04Components.attempt (noteBridgeAttemptIndex note + word)
    (noteBridgeFamily note) (noteBridgeLocalIndex note word) 0
    [(hashInitialIndex (noteCall note) word, 1), (densePrivateAddress note + 64 * word, 160)] 0

private theorem note_bridge_attempts : ∀ note, note < 4 → ∀ word, word < 2 →
    noteBridgeExpectedAttempt note word ∈ SmzaRp04Components.exactCsrAttempts := by
  intro note noteBound word wordBound
  interval_cases note <;> interval_cases word
  · apply chunk12_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0492)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks12]
    · decide
  · apply chunk12_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0493)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks12]
    · decide
  · apply chunk12_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0494)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks12]
    · decide
  · apply chunk12_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0494)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks12]
    · decide
  · apply chunk14_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0573)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks14]
    · decide
  · apply chunk14_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0573)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks14]
    · decide
  · apply chunk14_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0574)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks14]
    · decide
  · apply chunk14_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0574)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks14]
    · decide

def CsrTraceEquations (publicWords values : List Nat) : Prop :=
  ∀ (index : Nat) (expression : FieldExpression),
    SmzaRp04Components.exactCsrExpressions[index]? = some expression →
      values[index]? = evalFieldExpression publicWords [] values expression

private theorem csr_trace_zero_one {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values) :
    values[0]? = some 0 ∧ values[1]? = some 1 := by
  constructor
  · simpa [evalFieldExpression, fieldNormalize] using
      equations 0 (.constant 0) (by decide)
  · simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 1 (.constant 1) (by decide)

/-- The actual RP04 sponge source used for value/asset equals its raw dense word. -/
theorem accepted_note_source_bridge {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {note word : Nat} (noteBound : note < 4) (wordBound : word < 2) :
    spongeSourceWord packed (noteCall note) word =
      packedWord packed (densePrivateAddress note + 64 * word) := by
  obtain ⟨values, evaluated, allAttempts⟩ := accepted.2.2.2
  have equations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node
      SmzaRp04PackedAcceptance.csr_canonical_with_rows evaluated found
  have constants := csr_trace_zero_one equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have minusOneFound : values[160]? = some (fieldSub 0 1) := by
    simpa [evalFieldExpression, constants.1, constants.2] using
      equations 160 (.sub 0 1) (by decide)
  have minusOne : (values.getD 160 0 : F) = -1 := by
    simp only [List.getD_eq_getElem?_getD, minusOneFound, Option.getD_some]
    rw [field_sub_cast 0 1 (by decide)]
    simp
  have fieldEquation := accepted_csr_attempt_field_equality
    (allAttempts _ (note_bridge_attempts note noteBound word wordBound))
  simp only [noteBridgeExpectedAttempt, SmzaRp04Components.attempt, csrFieldSum,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    oneValue, minusOne, zeroValue, one_mul, neg_mul, add_zero] at fieldEquation
  have equality : (packed.getD (hashInitialIndex (noteCall note) word) 0 : F) =
      (packed.getD (densePrivateAddress note + 64 * word) 0 : F) := by
    exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using fieldEquation)
  have natural := canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (hashInitialIndex (noteCall note) word))
    (packed_word_canonical accepted.2.1 (densePrivateAddress note + 64 * word)) equality
  have divide : word / 8 = 0 := Nat.div_eq_of_lt (by omega)
  have modulo : word % 8 = word := Nat.mod_eq_of_lt (by omega)
  simpa [spongeSourceWord, divide, modulo] using natural

/-! ## RP04 dense range and natural reconstruction -/

private theorem canonical_small_of_product_zero {word : Nat}
    (bound : word < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)
    (zero : (((word : F) * ((word : F) - 1)) * ((word : F) - 2)) *
      ((word : F) - 3) = 0) : word < 4 := by
  rcases mul_eq_zero.mp zero with prior | three
  · rcases mul_eq_zero.mp prior with pair | two
    · rcases mul_eq_zero.mp pair with zero | one
      · have equal : word = 0 := canonical_nat_cast_injective bound (by decide) zero
        omega
      · have equal : word = 1 := canonical_nat_cast_injective bound (by decide)
          (sub_eq_zero.mp one)
        omega
    · have equal : word = 2 := canonical_nat_cast_injective bound (by decide)
        (sub_eq_zero.mp two)
      omega
  · have equal : word = 3 := canonical_nat_cast_injective bound (by decide)
      (sub_eq_zero.mp three)
    omega

private theorem accepted_dense_digit_bound {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {value digit : Nat} (valueBound : value < 4) (digitBound : digit < 30) :
    packed.getD (denseDigitAddress value digit) 0 < 4 := by
  let offset := 30 * value + digit
  let slot := offset / 64
  let lane := offset % 64
  have slotBound : slot < 4 := by
    dsimp only [slot, offset]
    omega
  have laneBound : lane < 64 := by
    exact Nat.mod_lt _ (by decide)
  have rootMember : 1183 + 6 * slot ∈ SmzaRp04Components.exactNonlinearRoots := by
    interval_cases slot <;> decide
  have actualZero := accepted_source_root_zero_at_lane (accepted := accepted) laneBound
    (root := 1183 + 6 * slot) rootMember
  let pub := fun index => (publicWords.getD index 0 : F)
  let rows := fun row => ((packedWitnessLaneRows packed lane).getD row 0 : F)
  have rootZero : fieldAt
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows
        (1183 + 6 * slot) = 0 :=
    (fieldAt_rp04_eq_rp03 pub rows (node := 1183 + 6 * slot) (by omega)).symm.trans
      actualZero
  have formula := V8Smz9SourceDenseRoots.actual_dense_radix_four_root_formula
    pub rows slot slotBound
  have rowBound : 247 + slot < 686 := by omega
  have rowValue : (packedWitnessLaneRows packed lane).getD (247 + slot) 0 =
      packed.getD ((247 + slot) * 64 + lane) 0 := by
    simp [packedWitnessLaneRows, relationRowCount, packingFactor, rowBound]
  have decomposition : lane + 64 * slot = offset := Nat.mod_add_div offset 64
  have coordinate : (247 + slot) * 64 + lane = denseDigitAddress value digit := by
    dsimp only [slot, lane, offset, denseDigitAddress] at decomposition ⊢
    omega
  have wordBound := packed_word_canonical accepted.2.1 (denseDigitAddress value digit)
  rw [formula] at rootZero
  dsimp only [rows] at rootZero
  rw [rowValue, coordinate] at rootZero
  exact canonical_small_of_product_zero wordBound rootZero

private theorem accepted_dense_top_bound {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {value : Nat} (valueBound : value < 4) :
    packed.getD (denseTopAddress value) 0 ≤ 1 := by
  let pub := fun index => (publicWords.getD index 0 : F)
  let rows := fun row => ((packedWitnessLaneRows packed value).getD row 0 : F)
  obtain ⟨actualValues, evaluated, zero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 value (by simp [packingFactor]; omega)) (show 1203 ∈
        SmzaRp04Components.exactNonlinearRoots by decide)
  have source := fieldAt_refines_source program.nonlinearExecutable publicWords
    (packedWitnessLaneRows packed value) actualValues
    SmzaRp04PackedAcceptance.nonlinear_canonical evaluated 1203
    (SmzaRp04PackedAcceptance.nonlinear_canonical.2 _ (by decide))
  have actualZero : fieldAt SmzaRp04Components.exactNonlinearExpressions
      pub rows 1203 = 0 := by
    change fieldAt SmzaRp04Components.exactNonlinearExpressions _ _ 1203 =
      (actualValues.getD 1203 0 : F) at source
    rw [source]
    simp [List.getD_eq_getElem?_getD, zero]
  have rootZero : fieldAt
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows 1203 = 0 :=
    (fieldAt_rp04_eq_rp03 pub rows (node := 1203) (by decide)).symm.trans actualZero
  have formula := V8Smz9SourceDenseRoots.actual_dense_top_root_formula pub rows
  have rowValue : (packedWitnessLaneRows packed value).getD 251 0 =
      packed.getD (251 * 64 + value) 0 := by
    simp [packedWitnessLaneRows, relationRowCount, packingFactor]
  have coordinate : 251 * 64 + value = denseTopAddress value := by
    simp [denseTopAddress]
  rw [formula] at rootZero
  dsimp only [rows] at rootZero
  rw [rowValue, coordinate] at rootZero
  have wordBound := packed_word_canonical accepted.2.1 (denseTopAddress value)
  rcases mul_eq_zero.mp rootZero with zero | one
  · have equal : packed.getD (denseTopAddress value) 0 = 0 :=
      canonical_nat_cast_injective wordBound (by decide) zero
    omega
  · have equal : packed.getD (denseTopAddress value) 0 = 1 :=
      canonical_nat_cast_injective wordBound (by decide) (sub_eq_zero.mp one)
    omega

def densePowerRoot (power : Nat) : Nat := if power = 0 then 1 else 129 + power

private theorem dense_power_nodes : ∀ power, power < 30 →
    SmzaRp04Components.exactCsrExpressions[densePowerRoot power]? =
      some (if power = 0 then .constant 1 else if power = 1 then .constant 4
        else .mul 130 (densePowerRoot (power - 1))) ∧
      4 ^ power < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  have checked : (List.range 30).all (fun power => decide
      (SmzaRp04Components.exactCsrExpressions[densePowerRoot power]? =
        some (if power = 0 then .constant 1 else if power = 1 then .constant 4
          else .mul 130 (densePowerRoot (power - 1))) ∧
        4 ^ power < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)) = true := by decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

private theorem dense_negative_nodes : ∀ power, power < 30 →
    SmzaRp04Components.exactCsrExpressions[160 + power]? =
      some (.sub 0 (densePowerRoot power)) := by
  have checked : (List.range 30).all (fun power => decide
      (SmzaRp04Components.exactCsrExpressions[160 + power]? =
        some (.sub 0 (densePowerRoot power)))) = true := by decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

private theorem dense_power_values {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values) :
    ∀ power, power < 30 → values[densePowerRoot power]? = some (4 ^ power) := by
  intro power
  induction power using Nat.strong_induction_on with
  | h power ih =>
      intro bound
      have node := dense_power_nodes power bound
      by_cases isZero : power = 0
      · subst power
        simpa [densePowerRoot] using (csr_trace_zero_one equations).2
      · by_cases isOne : power = 1
        · subst power
          simpa [densePowerRoot, evalFieldExpression, fieldNormalize,
            Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
            equations 130 (.constant 4) (by decide)
        · have prior := ih (power - 1) (by omega) (by omega)
          have fourValue : values[130]? = some 4 := by
            simpa [evalFieldExpression, fieldNormalize,
              Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
              equations 130 (.constant 4) (by decide)
          have current := equations (densePowerRoot power)
            (.mul 130 (densePowerRoot (power - 1)))
            (by simpa [isZero, isOne] using node.1)
          have product : 4 * 4 ^ (power - 1) = 4 ^ power := by
            rw [← pow_succ']
            congr 1
            omega
          simpa [evalFieldExpression, fourValue, prior, fieldMul, fieldNormalize,
            product, Nat.mod_eq_of_lt node.2] using current

private theorem dense_negative_values {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values) :
    (∀ power, power < 30 →
      (values.getD (160 + power) 0 : F) = -((4 ^ power : Nat) : F)) ∧
      (values.getD 191 0 : F) = -((2 ^ 60 : Nat) : F) := by
  have zeroValue := (csr_trace_zero_one equations).1
  constructor
  · intro power bound
    have powerValue := dense_power_values equations power bound
    have found : values[160 + power]? = some (fieldSub 0 (4 ^ power)) := by
      simpa [evalFieldExpression, zeroValue, powerValue] using
        equations (160 + power) (.sub 0 (densePowerRoot power))
          (dense_negative_nodes power bound)
    simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
    rw [field_sub_cast 0 (4 ^ power) (by have := (dense_power_nodes power bound).2; omega)]
    simp
  · have topValue : values[190]? = some (2 ^ 60) := by
      have evaluated := equations 190 (.constant (2 ^ 60)) (by decide)
      norm_num [evalFieldExpression, fieldNormalize,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] at evaluated ⊢
      exact evaluated
    have found : values[191]? = some (fieldSub 0 (2 ^ 60)) := by
      simpa [evalFieldExpression, zeroValue, topValue] using
        equations 191 (.sub 0 190) (by decide)
    simp only [List.getD_eq_getElem?_getD, found, Option.getD_some]
    rw [field_sub_cast 0 (2 ^ 60) (by decide)]
    simp

def denseNegativeTerms (value : Nat) : List (Nat × Nat) :=
  (List.range 30).map (fun digit => (denseDigitAddress value digit, 160 + digit)) ++
    [(denseTopAddress value, 191)]

private theorem dense_negative_terms_sum (values packed : List Nat) (value : Nat)
    (coefficients : ∀ digit, digit < 30 →
      (values.getD (160 + digit) 0 : F) = -((4 ^ digit : Nat) : F))
    (topCoefficient : (values.getD 191 0 : F) = -((2 ^ 60 : Nat) : F)) :
    csrFieldSum values packed (denseNegativeTerms value) =
      -(denseNaturalValue packed value : F) := by
  have digitMap :
      (List.range 30).map (fun digit =>
        (values.getD (160 + digit) 0 : F) *
          (packed.getD (denseDigitAddress value digit) 0 : F)) =
      ((List.range 30).map (fun digit =>
        4 ^ digit * packed.getD (denseDigitAddress value digit) 0)).map
          (fun term : Nat => -(term : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro digit member
    rw [coefficients digit (List.mem_range.mp member)]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul]
  unfold csrFieldSum denseNegativeTerms
  rw [List.map_append, List.sum_append, List.map_map, List.map_singleton,
    List.sum_singleton]
  change ((List.range 30).map (fun digit =>
    (values.getD (160 + digit) 0 : F) *
      (packed.getD (denseDigitAddress value digit) 0 : F))).sum +
    (values.getD 191 0 : F) * (packed.getD (denseTopAddress value) 0 : F) = _
  rw [digitMap, V8Smz9SemanticDenseRange.sum_neg_cast, topCoefficient]
  change -(V8Smz9SemanticDenseRange.radixFourSum
      (fun digit => packed.getD (denseDigitAddress value digit) 0) 30 : F) +
    -((2 ^ 60 : Nat) : F) * (packed.getD (denseTopAddress value) 0 : F) = _
  simp only [denseNaturalValue, Nat.cast_add, Nat.cast_mul, neg_mul, neg_add]

def denseExpectedAttempt (value : Nat) : CsrExecutableAttempt :=
  SmzaRp04Components.attempt (15640 + value) 6 value 0
    ((densePrivateAddress value, 1) :: denseNegativeTerms value) 0

private theorem dense_attempts : ∀ value, value < 4 →
    denseExpectedAttempt value ∈ SmzaRp04Components.exactCsrAttempts := by
  intro value valueBound
  interval_cases value
  all_goals
    apply chunk12_entry_mem_exact (chunk := SmzaRp04Components.exactCsrAttemptsChunk0488)
    · simp [SmzaRp04PackedAcceptanceData.csrAttemptChunks12]
    · decide

private theorem accepted_dense_natural_bound {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {value : Nat} (valueBound : value < 4) :
    denseNaturalValue packed value < 2 ^ 61 := by
  exact dense_natural_reconstruction_bound _ _
    (fun digit digitBound => accepted_dense_digit_bound accepted valueBound digitBound)
    (accepted_dense_top_bound accepted valueBound)

private theorem accepted_dense_field_reconstruction {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {value : Nat} (valueBound : value < 4) :
    (packed.getD (densePrivateAddress value) 0 : F) =
      (denseNaturalValue packed value : F) := by
  obtain ⟨values, evaluated, allAttempts⟩ := accepted.2.2.2
  have equations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node
      SmzaRp04PackedAcceptance.csr_canonical_with_rows evaluated found
  have coefficients := dense_negative_values equations
  have negativeSum := dense_negative_terms_sum values packed value
    coefficients.1 coefficients.2
  have fieldEquation := accepted_csr_attempt_field_equality
    (allAttempts _ (dense_attempts value valueBound))
  have constants := csr_trace_zero_one equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  simp only [denseExpectedAttempt, SmzaRp04Components.attempt] at fieldEquation
  rw [V8Smz9SemanticDenseRange.csr_field_sum_cons, oneValue, one_mul,
    negativeSum, zeroValue] at fieldEquation
  exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using fieldEquation)

/-- Each of the four RP04 note values has the natural 61-bit range needed to
lift the field balance without wraparound. -/
theorem accepted_note_value_bound {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {note : Nat} (noteBound : note < 4) :
    (projectNote packed (noteCall note)).value < 2 ^ 61 := by
  have fieldEq := accepted_dense_field_reconstruction accepted (value := note) noteBound
  have sourceBound := packed_word_canonical accepted.2.1 (densePrivateAddress note)
  have naturalBound := accepted_dense_natural_bound accepted (value := note) noteBound
  have naturalEq : packed.getD (densePrivateAddress note) 0 =
      denseNaturalValue packed note :=
    canonical_nat_cast_injective sourceBound (by
      have modulus : 2 ^ 61 <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by decide
      omega) fieldEq
  change spongeSourceWord packed (noteCall note) 0 < 2 ^ 61
  rw [accepted_note_source_bridge accepted noteBound (by decide)]
  simpa only [Nat.mul_zero, Nat.add_zero, packedWord, naturalEq] using naturalBound

/-! ## Asset membership and semantic natural balance -/

private theorem asset_root_member {note : Nat} (bound : note < 4) :
    (assetRootAt note).root ∈ SmzaRp04Components.exactNonlinearRoots := by
  interval_cases note <;> decide

theorem accepted_active_note_asset_member {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {note : Nat} (noteBound : note < 4) (active : publicWords.getD note 0 = 1) :
    ∃ slot, slot < 4 ∧ publicWords.getD (54 + slot) 0 ≠ balancePaddingAssetId ∧
      (projectNote packed (noteCall note)).assetId = publicWords.getD (54 + slot) 0 := by
  have entry := asset_root_at_valid noteBound
  have actualZero := accepted_source_root_zero accepted (asset_root_member noteBound)
  let pub := fun index => (publicWords.getD index 0 : F)
  let rows := fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)
  have rootZero : fieldAt
      V8Smz9RelationProgramComponentsGenerated.exactNonlinearExpressions pub rows
        (assetRootAt note).root = 0 :=
    (fieldAt_rp04_eq_rp03 pub rows (node := (assetRootAt note).root)
      (by interval_cases note <;> decide)).symm.trans actualZero
  rw [actual_asset_root_formula (assetRootAt note) entry.1] at rootZero
  have validCopy := entry.1
  obtain ⟨_, rowBound, address, _, _, _, _, _, _, _, _, _, _⟩ := validCopy
  have addressNote : (assetRootAt note).row * 64 = densePrivateAddress note + 64 := by
    simpa only [entry.2] using address
  have rowValue : (packedWitnessLaneRows packed 0).getD (assetRootAt note).row 0 =
      packedWord packed (densePrivateAddress note + 64) := by
    simp [packedWitnessLaneRows, List.getD_eq_getElem?_getD, rowBound,
      relationRowCount, packingFactor, packedWord, addressNote]
  have activeEntry : publicWords.getD (assetRootAt note).note 0 = 1 := by
    simpa only [entry.2] using active
  dsimp only [pub, rows] at rootZero
  simp only [activeEntry, Nat.cast_one, one_mul, rowValue] at rootZero
  obtain ⟨slot, slotBound, nonpadding, equal⟩ := four_asset_factors_zero
    (candidates := fun slot => (publicWords.getD (54 + slot) 0 : F)) rootZero
  have naturalAsset : packedWord packed (densePrivateAddress note + 64) =
      publicWords.getD (54 + slot) 0 :=
    canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
      (canonical_getD publicWords accepted.1.2 _) equal
  refine ⟨slot, slotBound, ?_, ?_⟩
  · intro padding
    exact nonpadding (congrArg (fun value : Nat => (value : F)) padding)
  · change spongeSourceWord packed (noteCall note) 1 = _
    rw [accepted_note_source_bridge accepted noteBound (by decide)]
    exact naturalAsset

theorem admitted_balance_public_fields {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    publicWords.getD 44 0 = statement.fee ∧ publicWords.getD 45 0 = 0 ∧
    publicWords.getD 46 0 = 0 ∧
    publicWords.getD 58 0 = statement.compatibility.enabled ∧
    publicWords.getD 59 0 = statement.compatibility.assetId ∧
    publicWords.getD 61 0 = statement.compatibility.issuanceSign ∧
    publicWords.getD 62 0 = statement.compatibility.issuanceMagnitude := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, signZero, magnitudeZero, _⟩ := domain.2.1
  rw [← domain.1]
  exact ⟨encoded_balance_scalar statement domain.2.1 (index := 0) (by decide),
    (encoded_balance_scalar statement domain.2.1 (index := 1) (by decide)).trans signZero,
    (encoded_balance_scalar statement domain.2.1 (index := 2) (by decide)).trans magnitudeZero,
    encoded_compatibility_scalar statement domain.2.1 (index := 0) (by decide),
    encoded_compatibility_scalar statement domain.2.1 (index := 1) (by decide),
    encoded_compatibility_scalar statement domain.2.1 (index := 3) (by decide),
    encoded_compatibility_scalar statement domain.2.1 (index := 4) (by decide)⟩

theorem admitted_balance_asset {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    publicWords.getD (54 + slot) 0 = wordAt statement.balanceAssets slot := by
  rw [← domain.1]
  exact encoded_balance_asset statement domain.2.1 bound

private theorem admitted_raw_note_flag_one {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {note : Nat} (bound : note < 4) (active : publicWords.getD note 0 ≠ 0) :
    publicWords.getD note 0 = 1 := by
  by_cases input : note < 2
  · have flag := V8Smz9SemanticAssetMembership.encoded_input_flag
      statement domain.2.1 input
    rw [← domain.1, flag] at active ⊢
    exact admitted_input_flag_one statement domain.2.1 input active
  · have outputBound : note - 2 < 2 := by omega
    have index : 2 + (note - 2) = note := by omega
    have flag := V8Smz9SemanticAssetMembership.encoded_output_flag
      statement domain.2.1 outputBound
    rw [index] at flag
    rw [← domain.1, flag] at active ⊢
    exact admitted_output_flag_one statement domain.2.1 outputBound active

private theorem admitted_public_asset_field_distinct {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    NonpaddingDistinct (fun index => (publicWords.getD (54 + index) 0 : F))
      (balancePaddingAssetId : F) := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, assets, _⟩ := domain.2.1
  have distinct := V8Smz9SemanticInterpolation.canonical_balance_assets_nonpadding_distinct
    statement.balanceAssets assets
  intro left right different leftReal rightReal equal
  dsimp only at leftReal rightReal equal
  rw [admitted_balance_asset domain left.isLt] at leftReal equal
  rw [admitted_balance_asset domain right.isLt] at rightReal equal
  exact distinct left right different leftReal rightReal equal

theorem admitted_active_weight_indicator {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {note slot : Nat} (noteBound : note < 4) (slotBound : slot < 4)
    (active : publicWords.getD note 0 = 1) :
    sourceWeight (fun index => (publicWords.getD index 0 : F)) slot
      ((projectNote packed (noteCall note)).assetId : F) =
      if (projectNote packed (noteCall note)).assetId = publicWords.getD (54 + slot) 0
        then 1 else 0 := by
  have distinct := admitted_public_asset_field_distinct domain
  obtain ⟨chosen, chosenBound, nonpadding, matched⟩ :=
    accepted_active_note_asset_member domain.2.2 noteBound active
  have member : ∃ selected : Fin 4,
      (publicWords.getD (54 + selected.val) 0 : F) ≠ (balancePaddingAssetId : F) ∧
      ((projectNote packed (noteCall note)).assetId : F) =
        (publicWords.getD (54 + selected.val) 0 : F) := by
    refine ⟨⟨chosen, chosenBound⟩, ?_, congrArg (fun value : Nat => (value : F)) matched⟩
    intro equal
    exact nonpadding (canonical_nat_cast_injective
      (canonical_getD publicWords domain.2.2.1.2 _) (by decide) equal)
  have generic := interpolationWeight_eq_indicator
    (fun index => (publicWords.getD (54 + index) 0 : F)) (balancePaddingAssetId : F)
    ⟨slot, slotBound⟩ ((projectNote packed (noteCall note)).assetId : F) distinct member
  rw [← sourceWeight_eq_interpolationWeight (fun index => (publicWords.getD index 0 : F))
    ⟨slot, slotBound⟩] at generic
  by_cases same : (projectNote packed (noteCall note)).assetId =
      publicWords.getD (54 + slot) 0
  · simpa only [same, if_pos rfl] using generic
  · have fieldDifferent : ((projectNote packed (noteCall note)).assetId : F) ≠
        (publicWords.getD (54 + slot) 0 : F) := by
      intro equal
      exact same (canonical_nat_cast_injective
        (V8Smz9SemanticDecoder.project_note_field_shape domain.2.2.2.1 _).1
        (canonical_getD publicWords domain.2.2.1.2 _) equal)
    simpa only [if_neg same, if_neg fieldDifferent] using generic

def noteContribution (publicWords packed : List Nat) (asset note : Nat) : Nat :=
  if publicWords.getD note 0 = 1 ∧
      (projectNote packed (noteCall note)).assetId = asset
  then (projectNote packed (noteCall note)).value else 0

def noteInputSum (publicWords packed : List Nat) (asset : Nat) : Nat :=
  noteContribution publicWords packed asset 0 + noteContribution publicWords packed asset 1

def noteOutputSum (publicWords packed : List Nat) (asset : Nat) : Nat :=
  noteContribution publicWords packed asset 2 + noteContribution publicWords packed asset 3

private theorem packed_lane_zero_row (packed : List Nat) {row : Nat} (bound : row < 686) :
    (packedWitnessLaneRows packed 0).getD row 0 = packedWord packed (row * 64) := by
  simp [packedWitnessLaneRows, relationRowCount, packingFactor,
    List.getD_eq_getElem?_getD, bound, packedWord]

private theorem accepted_lane_note_word {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    {note word : Nat} (noteBound : note < 4) (wordBound : word < 2) :
    (packedWitnessLaneRows packed 0).getD
      (V8Smz9SemanticBalance.valueRow note + word) 0 =
        spongeSourceWord packed (noteCall note) word := by
  have valueRowBound : V8Smz9SemanticBalance.valueRow note ≤ 80 := by
    interval_cases note <;> decide
  have address : (valueRow note + word) * 64 =
      densePrivateAddress note + 64 * word := by
    rw [Nat.add_mul, (value_row_source noteBound).2.1, Nat.mul_comm word 64]
  rw [packed_lane_zero_row packed (by omega), address]
  exact (accepted_note_source_bridge accepted noteBound wordBound).symm

private theorem admitted_source_contribution {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {note slot : Nat} (noteBound : note < 4) (slotBound : slot < 4) :
    sourceContribution (fun index => (publicWords.getD index 0 : F))
      (fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)) slot note =
      (noteContribution publicWords packed (wordAt statement.balanceAssets slot) note : F) := by
  have value := accepted_lane_note_word domain.2.2 noteBound (word := 0) (by decide)
  have asset := accepted_lane_note_word domain.2.2 noteBound (word := 1) (by decide)
  have publicAsset := admitted_balance_asset domain slotBound
  simp only [Nat.add_zero] at value
  unfold sourceContribution
  dsimp only
  rw [value, asset]
  change sourceWeight (fun index => (publicWords.getD index 0 : F)) slot
      ((projectNote packed (noteCall note)).assetId : F) *
      ((publicWords.getD note 0 : F) * ((projectNote packed (noteCall note)).value : F)) = _
  by_cases inactive : publicWords.getD note 0 = 0
  · simp only [noteContribution, inactive, Nat.cast_zero, zero_mul, mul_zero,
      zero_ne_one, false_and, if_false]
  · have active := admitted_raw_note_flag_one domain noteBound inactive
    rw [admitted_active_weight_indicator domain noteBound slotBound active]
    rw [publicAsset]
    by_cases same : (projectNote packed (noteCall note)).assetId =
        wordAt statement.balanceAssets slot
    · simp only [noteContribution, active, same, if_pos, and_self, Nat.cast_one, one_mul]
    · simp only [noteContribution, active, same, if_false, and_false,
        Nat.cast_one, one_mul, zero_mul, Nat.cast_zero]

private theorem admitted_source_delta {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    sourceDelta (fun index => (publicWords.getD index 0 : F))
      (fun row => ((packedWitnessLaneRows packed 0).getD row 0 : F)) slot =
      (noteInputSum publicWords packed (wordAt statement.balanceAssets slot) : F) -
        (noteOutputSum publicWords packed (wordAt statement.balanceAssets slot) : F) := by
  rw [sourceDelta, admitted_source_contribution domain (by decide : 0 < 4) bound,
    admitted_source_contribution domain (by decide : 1 < 4) bound,
    admitted_source_contribution domain (by decide : 2 < 4) bound,
    admitted_source_contribution domain (by decide : 3 < 4) bound]
  simp only [noteInputSum, noteOutputSum, Nat.cast_add, sub_sub]

private theorem two_step_conditional_sum (first second : Prop)
    [Decidable first] [Decidable second] (left right : Nat) :
    (if second then (if first then left else 0) + right else
      (if first then left else 0)) =
      (if first then left else 0) + (if second then right else 0) := by
  by_cases hFirst : first <;> by_cases hSecond : second <;> simp [hFirst, hSecond]

private theorem admitted_input_sum_is_typed {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) (asset : Nat) :
    inputValueForAsset (projectTypedWitness statement packed) asset =
      noteInputSum publicWords packed asset := by
  have flag0 : publicWords.getD 0 0 = flagAt statement.inputFlags 0 := by
    rw [← domain.1]
    exact V8Smz9SemanticAssetMembership.encoded_input_flag statement domain.2.1 (by decide)
  have flag1 : publicWords.getD 1 0 = flagAt statement.inputFlags 1 := by
    rw [← domain.1]
    exact V8Smz9SemanticAssetMembership.encoded_input_flag statement domain.2.1 (by decide)
  have note0 : projectNote packed (noteCall 0) = (projectInput statement packed 0).note := rfl
  have note1 : projectNote packed (noteCall 1) = (projectInput statement packed 1).note := rfl
  have active0 : flagAt statement.inputFlags 0 =
      (projectInput statement packed 0).active := rfl
  have active1 : flagAt statement.inputFlags 1 =
      (projectInput statement packed 1).active := rfl
  have range : List.range 2 = [0, 1] := rfl
  simp only [inputValueForAsset, projectTypedWitness, range,
    List.map_cons, List.map_nil, List.foldl_cons, List.foldl_nil,
    noteInputSum, noteContribution, flag0, flag1, note0, note1, active0, active1,
    Nat.zero_add]
  exact two_step_conditional_sum _ _ _ _

private theorem admitted_output_sum_is_typed {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) (asset : Nat) :
    outputValueForAsset (projectTypedWitness statement packed) asset =
      noteOutputSum publicWords packed asset := by
  have flag0 : publicWords.getD 2 0 = flagAt statement.outputFlags 0 := by
    rw [← domain.1]
    simpa using V8Smz9SemanticAssetMembership.encoded_output_flag statement domain.2.1
      (output := 0) (by decide)
  have flag1 : publicWords.getD 3 0 = flagAt statement.outputFlags 1 := by
    rw [← domain.1]
    simpa using V8Smz9SemanticAssetMembership.encoded_output_flag statement domain.2.1
      (output := 1) (by decide)
  have note0 : projectNote packed (noteCall 2) = (projectOutput statement packed 0).note := rfl
  have note1 : projectNote packed (noteCall 3) = (projectOutput statement packed 1).note := rfl
  have active0 : flagAt statement.outputFlags 0 =
      (projectOutput statement packed 0).active := rfl
  have active1 : flagAt statement.outputFlags 1 =
      (projectOutput statement packed 1).active := rfl
  have range : List.range 2 = [0, 1] := rfl
  simp only [outputValueForAsset, projectTypedWitness, range,
    List.map_cons, List.map_nil, List.foldl_cons, List.foldl_nil,
    noteOutputSum, noteContribution, flag0, flag1, note0, note1, active0, active1,
    Nat.zero_add]
  exact two_step_conditional_sum _ _ _ _

private theorem admitted_native_slot_iff {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    wordAt statement.balanceAssets slot = nativeAssetId ↔ slot = 0 := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, assets, _⟩ := domain.2.1
  constructor
  · intro native
    by_contra nonzero
    have positive : 0 < slot := by omega
    have firstReal : wordAt statement.balanceAssets 0 ≠ balancePaddingAssetId := by
      rw [assets.2.1]
      decide
    have slotReal : wordAt statement.balanceAssets slot ≠ balancePaddingAssetId := by
      rw [native]
      decide
    have ordered := assets.2.2.2.1 0 slot positive bound firstReal slotReal
    rw [assets.2.1, native] at ordered
    exact Nat.lt_irrefl _ ordered
  · rintro rfl
    exact assets.2.1

private theorem admitted_expected_field {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    sourceExpected (fun index => (publicWords.getD index 0 : F)) slot =
      typedExpectedField statement (wordAt statement.balanceAssets slot) := by
  have fields := admitted_balance_public_fields domain
  have asset := admitted_balance_asset domain bound
  have nativeIff := admitted_native_slot_iff domain bound
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, compatibility, _⟩ := domain.2.1
  by_cases native : wordAt statement.balanceAssets slot = nativeAssetId
  · have slotZero := nativeIff.mp native
    rw [sourceExpected, if_pos slotZero, typedExpectedField, if_pos native,
      fields.1, fields.2.1, fields.2.2.1]
    simp [signedFieldValue]
  · have slotNonzero : slot ≠ 0 := by
      intro zero
      exact native (nativeIff.mpr zero)
    have comparison : ((wordAt statement.balanceAssets slot : Nat) : F) =
        (statement.compatibility.assetId : F) ↔
        statement.compatibility.assetId = wordAt statement.balanceAssets slot := by
      constructor
      · intro equal
        have slotCanonical : wordAt statement.balanceAssets slot <
            Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
          rw [← asset]
          exact canonical_getD publicWords domain.2.2.1.2 _
        have stableCanonical : statement.compatibility.assetId <
            Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
          rw [← fields.2.2.2.2.1]
          exact canonical_getD publicWords domain.2.2.1.2 _
        exact (canonical_nat_cast_injective slotCanonical stableCanonical equal).symm
      · intro equal
        rw [equal]
    simp only [sourceExpected, if_neg slotNonzero, asset, fields.2.2.2.1,
      fields.2.2.2.2.1, fields.2.2.2.2.2.1, fields.2.2.2.2.2.2,
      typedExpectedField, if_neg native, comparison]
    rcases compatibility.1 with disabled | enabled
    · simp [disabled]
    · rw [enabled]
      by_cases matching : statement.compatibility.assetId = wordAt statement.balanceAssets slot
      · simp only [matching, if_true, and_self, Nat.cast_one, one_mul]
        rcases compatibility.2.1 with signZero | signOne
        · simp [signedFieldValue, signZero]
        · simp only [signedFieldValue, signOne, if_true, Nat.cast_one]
          ring
      · simp [matching]

private theorem admitted_typed_field_balance {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    (inputValueForAsset (projectTypedWitness statement packed)
        (wordAt statement.balanceAssets slot) : F) -
      (outputValueForAsset (projectTypedWitness statement packed)
        (wordAt statement.balanceAssets slot) : F) =
      typedExpectedField statement (wordAt statement.balanceAssets slot) := by
  have equation := accepted_source_balance_equation domain.2.2 bound
  rw [admitted_source_delta domain bound, admitted_expected_field domain bound] at equation
  simpa only [admitted_input_sum_is_typed domain,
    admitted_output_sum_is_typed domain] using equation

private theorem note_contribution_bound {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (asset : Nat) {note : Nat} (bound : note < 4) :
    noteContribution publicWords packed asset note < 2 ^ 61 := by
  unfold noteContribution
  split
  · exact accepted_note_value_bound accepted bound
  · decide

private theorem admitted_typed_value_sum_bounds {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) (asset : Nat) :
    inputValueForAsset (projectTypedWitness statement packed) asset < 2 ^ 62 ∧
    outputValueForAsset (projectTypedWitness statement packed) asset < 2 ^ 62 := by
  rw [admitted_input_sum_is_typed domain, admitted_output_sum_is_typed domain]
  have first := note_contribution_bound domain.2.2 asset (note := 0) (by decide)
  have second := note_contribution_bound domain.2.2 asset (note := 1) (by decide)
  have third := note_contribution_bound domain.2.2 asset (note := 2) (by decide)
  have fourth := note_contribution_bound domain.2.2 asset (note := 3) (by decide)
  unfold noteInputSum noteOutputSum
  constructor <;> omega

/-- Actual RP04 packed acceptance implies full natural-number per-asset
conservation for the RP04 call-schedule projection. -/
theorem accepted_balance {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    V8BalanceValid statement (projectTypedWitness statement packed) := by
  intro slot bound
  change wordAt statement.balanceAssets slot = balancePaddingAssetId ∨ _
  by_cases padding : wordAt statement.balanceAssets slot = balancePaddingAssetId
  · exact Or.inl padding
  · right
    have equation := admitted_typed_field_balance domain bound
    have sums := admitted_typed_value_sum_bounds domain
      (wordAt statement.balanceAssets slot)
    obtain ⟨_, _, _, _, _, _, _, _, _, _, feeBound, _, _, _, _, compatibility, _⟩ :=
      domain.2.1
    have feeRange : statement.fee < 2 ^ 61 := feeBound
    have magnitudeRange : statement.compatibility.issuanceMagnitude < 2 ^ 61 := by
      have bounded := compatibility.2.2.1
      change statement.compatibility.issuanceMagnitude < 2 ^ 56 at bounded
      omega
    have inputCanonical : inputValueForAsset (projectTypedWitness statement packed)
        (wordAt statement.balanceAssets slot) <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
      have h := pair_sum_extra_canonical sums.1 (extra := 0) (by decide)
      simpa only [Nat.add_zero,
        Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using h
    have outputCanonical : outputValueForAsset (projectTypedWitness statement packed)
        (wordAt statement.balanceAssets slot) <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
      have h := pair_sum_extra_canonical sums.2 (extra := 0) (by decide)
      simpa only [Nat.add_zero,
        Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using h
    by_cases native : wordAt statement.balanceAssets slot = nativeAssetId
    · rw [if_pos native]
      simp only [typedExpectedField, if_pos native] at equation
      apply canonical_nat_cast_injective inputCanonical
        (pair_sum_extra_canonical sums.2 feeRange)
      rw [Nat.cast_add]
      linear_combination equation
    · rw [if_neg native]
      simp only [typedExpectedField, if_neg native] at equation
      by_cases stable : statement.compatibility.enabled = 1 ∧
          statement.compatibility.assetId = wordAt statement.balanceAssets slot
      · rw [if_pos stable]
        rw [if_pos stable] at equation
        by_cases mint : statement.compatibility.issuanceSign = 1
        · rw [if_pos mint]
          rw [if_pos mint] at equation
          apply canonical_nat_cast_injective
            (pair_sum_extra_canonical sums.1 magnitudeRange) outputCanonical
          rw [Nat.cast_add]
          linear_combination equation
        · rw [if_neg mint]
          rw [if_neg mint] at equation
          apply canonical_nat_cast_injective inputCanonical
            (pair_sum_extra_canonical sums.2 magnitudeRange)
          rw [Nat.cast_add]
          linear_combination equation
      · rw [if_neg stable]
        rw [if_neg stable] at equation
        exact canonical_nat_cast_injective inputCanonical outputCanonical
          (sub_eq_zero.mp equation)

theorem accepted_native_balance {statement : V8PublicStatement} {packed : List Nat}
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (accepted : program.AcceptsPacked (encodePublicStatement statement) packed) :
    inputValueForAsset (projectTypedWitness statement packed) nativeAssetId =
      outputValueForAsset (projectTypedWitness statement packed) nativeAssetId + statement.fee := by
  have domain : CanonicalPublicPackedDomain statement
      (encodePublicStatement statement) packed := ⟨rfl, canonical, accepted⟩
  have balance := accepted_balance domain 0 (by decide)
  have native := (admitted_native_slot_iff domain (slot := 0) (by decide)).mpr rfl
  rw [native] at balance
  have paddingNe : nativeAssetId ≠ balancePaddingAssetId := by
    rw [balance_padding_asset_id_eq]
    decide
  simpa only [paddingNe, false_or, if_pos rfl, ite_true] using balance

/-- A fully satisfied actual RP04 recovered candidate yields the full natural
balance statement for the RP04 projection.  Canonical public words are the
same independent public-format premise used by the actual extractor. -/
theorem fully_satisfied_balance {statement : V8PublicStatement}
    (rows : SmzaQ38Recovery.RecoveredRows)
    (canonicalStatement : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (canonicalPublic : CanonicalPublicWords (encodePublicStatement statement))
    (satisfied : PiopExtraction.FullySatisfied
      (SmzaRp04ActualProgram.recoveredCandidate
        (encodePublicStatement statement) rows).system) :
    V8BalanceValid statement
      (projectTypedWitness statement (SmzaQ38Recovery.packedFromRows rows)) := by
  have accepted :=
    SmzaRp04ActualProgram.recovered_candidate_satisfaction_supplies_actual_program
      (encodePublicStatement statement) rows canonicalPublic satisfied
  exact accepted_balance ⟨rfl, canonicalStatement, accepted⟩

theorem fully_satisfied_native_balance {statement : V8PublicStatement}
    (rows : SmzaQ38Recovery.RecoveredRows)
    (canonicalStatement : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (canonicalPublic : CanonicalPublicWords (encodePublicStatement statement))
    (satisfied : PiopExtraction.FullySatisfied
      (SmzaRp04ActualProgram.recoveredCandidate
        (encodePublicStatement statement) rows).system) :
    inputValueForAsset
        (projectTypedWitness statement (SmzaQ38Recovery.packedFromRows rows)) nativeAssetId =
      outputValueForAsset
          (projectTypedWitness statement (SmzaQ38Recovery.packedFromRows rows)) nativeAssetId +
        statement.fee := by
  have accepted :=
    SmzaRp04ActualProgram.recovered_candidate_satisfaction_supplies_actual_program
      (encodePublicStatement statement) rows canonicalPublic satisfied
  exact accepted_native_balance canonicalStatement accepted

end
end HegemonCrypto.SmallWood.SmzaRp04BalanceCore
