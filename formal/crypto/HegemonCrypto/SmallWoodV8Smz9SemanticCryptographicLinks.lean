import HegemonCrypto.SmallWoodV8Smz9HashRootCertificate

/-! Arbitrary accepted source hash traces have a unique initial-state-only DAG replay.
Primitive correspondence is a separate endpoint. -/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (fieldAt fieldAt_eq expressionField fieldAt_refines_source)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
  (actual_node_field_equation)

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

noncomputable section

/-- Safe intervals remove public words and all unrelated witness rows. -/
theorem fieldAt_congr_on_span (pub₁ pub₂ rows₁ rows₂ : Nat → F)
    (lower upper : Nat) (upperBound : upper ≤ 686)
    (agree : ∀ row, lower ≤ row → row < upper → rows₁ row = rows₂ row)
    (node : Nat) (lowerBound : lower ≤ (exactSpan node).1)
    (higherBound : (exactSpan node).2 ≤ upper) :
    fieldAt exactNonlinearExpressions pub₁ rows₁ node =
      fieldAt exactNonlinearExpressions pub₂ rows₂ node := by
  induction node using Nat.strong_induction_on with
  | h node ih =>
    cases found : exactNonlinearExpressions[node]? with
    | none => simp [fieldAt_eq, found]
    | some expression =>
      have canonical :=
        hgv8rp03_nonlinear_expression_program_is_canonical.1 node expression found
      have span := exact_span_certificate found
      rw [actual_node_field_equation pub₁ rows₁ found,
        actual_node_field_equation pub₂ rows₂ found]
      cases expression <;> simp only [FieldExpression.CanonicalAt] at canonical
      all_goals simp only [expressionSpan] at span
      case constant n => rfl
      case witnessRow row =>
        apply agree row <;> simp_all
      case publicWord word => simp_all; omega
      case inverse a => simp_all; omega
      case bit a b => simp_all; omega
      case selectEqual a b c d => simp_all; omega
      case add a b | sub a b | mul a b =>
        have loA : lower ≤ (exactSpan a).1 := by
          rw [span] at lowerBound
          exact lowerBound.trans (min_le_left _ _)
        have loB : lower ≤ (exactSpan b).1 := by
          rw [span] at lowerBound
          exact lowerBound.trans (min_le_right _ _)
        have hiA : (exactSpan a).2 ≤ upper := by
          rw [span] at higherBound
          exact (le_max_left _ _).trans higherBound
        have hiB : (exactSpan b).2 ≤ upper := by
          rw [span] at higherBound
          exact (le_max_right _ _).trans higherBound
        simp only [expressionField, ih a canonical.1 loA hiA, ih b canonical.2 loB hiB]
      case neg a =>
        simp only [expressionField]
        rw [ih a canonical (by simpa only [span] using lowerBound)
          (by simpa only [span] using higherBound)]

def laneField (packed : List Nat) (lane row : Nat) : F :=
  ((packedWitnessLaneRows packed lane).getD row 0 : F)

theorem accepted_hash_recurrence {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {group wire lane : Nat} (groupBound : group < 2) (wireBound : wire < 166)
    (laneBound : lane < 64) :
    laneField packed lane (hashRow group wire) =
      fieldAt exactNonlinearExpressions (fun n => (publicWords.getD n 0 : F))
        (laneField packed lane) (hashRootPair group wire).2 := by
  obtain ⟨rootExpr, rowExpr, rootMember, _, _⟩ :=
    exact_hash_roots_valid groupBound wireBound
  obtain ⟨values, evaluated, rootZero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 lane laneBound) rootMember
  have source := fieldAt_refines_source hgv8rp03ProgramComponents.nonlinearExecutable
    publicWords (packedWitnessLaneRows packed lane) values
    hgv8rp03_nonlinear_expression_program_is_canonical evaluated
    (hashRootPair group wire).1
    (hgv8rp03_nonlinear_expression_program_is_canonical.2 _ rootMember)
  change fieldAt exactNonlinearExpressions (fun n => (publicWords.getD n 0 : F))
    (laneField packed lane) (hashRootPair group wire).1 =
      (values.getD (hashRootPair group wire).1 0 : F) at source
  have zero : fieldAt exactNonlinearExpressions
      (fun n => (publicWords.getD n 0 : F)) (laneField packed lane)
      (hashRootPair group wire).1 = 0 := by
    rw [source]
    change (values[(hashRootPair group wire).1]?.getD 0 : F) = 0
    rw [rootZero]
    rfl
  rw [actual_node_field_equation _ _ rootExpr] at zero
  simp only [expressionField] at zero
  rw [actual_node_field_equation _ _ rowExpr] at zero
  exact sub_eq_zero.mp zero

def HashRecurrence (group : Nat) (pub rows : Nat → F) : Prop :=
  ∀ wire, wire < 166 → rows (hashRow group wire) =
    fieldAt exactNonlinearExpressions pub rows (hashRootPair group wire).2

/-- The entire source hash trace is uniquely fixed by its 16 initial words.
Public words and unrelated witness rows may differ arbitrarily. -/
theorem hash_trace_unique {group : Nat} (groupBound : group < 2)
    (pub₁ pub₂ rows₁ rows₂ : Nat → F)
    (first : HashRecurrence group pub₁ rows₁)
    (second : HashRecurrence group pub₂ rows₂)
    (initial : ∀ offset, offset < 16 →
      rows₁ (283 + 182 * group + offset) = rows₂ (283 + 182 * group + offset)) :
    ∀ offset, offset < 182 →
      rows₁ (283 + 182 * group + offset) = rows₂ (283 + 182 * group + offset) := by
  intro offset
  induction offset using Nat.strong_induction_on with
  | h offset ih =>
    intro bound
    by_cases isInitial : offset < 16
    · exact initial offset isInitial
    · have wireBound : offset - 16 < 166 := by omega
      have rowEq : hashRow group (offset - 16) = 283 + 182 * group + offset := by
        unfold hashRow
        omega
      rw [← rowEq, first _ wireBound, second _ wireBound]
      obtain ⟨_, _, _, lower, upper⟩ := exact_hash_roots_valid groupBound wireBound
      apply fieldAt_congr_on_span pub₁ pub₂ rows₁ rows₂
        (283 + 182 * group) (hashRow group (offset - 16))
        (by unfold hashRow; omega) _ _ lower upper
      intro row low high
      rw [rowEq] at high
      have smaller : row - (283 + 182 * group) < offset := by omega
      have equality := ih (row - (283 + 182 * group)) smaller (by omega)
      have indexEq : 283 + 182 * group + (row - (283 + 182 * group)) = row := by omega
      simpa only [indexEq] using equality

theorem accepted_hash_trace_unique
    {public₁ public₂ packed₁ packed₂ : List Nat}
    (first : hgv8rp03ProgramComponents.AcceptsPacked public₁ packed₁)
    (second : hgv8rp03ProgramComponents.AcceptsPacked public₂ packed₂)
    {group lane₁ lane₂ : Nat} (groupBound : group < 2)
    (laneBound₁ : lane₁ < 64) (laneBound₂ : lane₂ < 64)
    (initial : ∀ offset, offset < 16 →
      laneField packed₁ lane₁ (283 + 182 * group + offset) =
        laneField packed₂ lane₂ (283 + 182 * group + offset)) :
    ∀ offset, offset < 182 →
      laneField packed₁ lane₁ (283 + 182 * group + offset) =
        laneField packed₂ lane₂ (283 + 182 * group + offset) := by
  exact hash_trace_unique groupBound
    (fun n => (public₁.getD n 0 : F)) (fun n => (public₂.getD n 0 : F))
    (laneField packed₁ lane₁) (laneField packed₂ lane₂)
    (fun _ bound => accepted_hash_recurrence first groupBound bound laneBound₁)
    (fun _ bound => accepted_hash_recurrence second groupBound bound laneBound₂) initial

/-- Construct a source trace from only the initial 16 field words, with no
accepted witness or desired primitive output as an input. -/
def sourceHashReplay (group : Nat) (initial : Nat → F) : Nat → F :=
  Nat.strongRec fun offset earlier =>
    if offset < 16 then initial offset
    else if offset < 182 then
      fieldAt exactNonlinearExpressions (fun _ => 0)
        (fun row => if h : 283 + 182 * group ≤ row ∧ row < 283 + 182 * group + offset
          then earlier (row - (283 + 182 * group)) (by omega) else 0)
        (hashRootPair group (offset - 16)).2
    else 0

theorem sourceHashReplay_eq (group : Nat) (initial : Nat → F) (offset : Nat) :
    sourceHashReplay group initial offset =
      if offset < 16 then initial offset
      else if offset < 182 then
        fieldAt exactNonlinearExpressions (fun _ => 0)
          (fun row => if 283 + 182 * group ≤ row ∧ row < 283 + 182 * group + offset
            then sourceHashReplay group initial (row - (283 + 182 * group)) else 0)
          (hashRootPair group (offset - 16)).2
      else 0 := by
  unfold sourceHashReplay
  rw [Nat.strongRec_eq]
  rfl

theorem hash_recurrence_refines_source_replay {group : Nat} (groupBound : group < 2)
    (pub rows : Nat → F) (recurrence : HashRecurrence group pub rows) :
    ∀ offset, offset < 182 → rows (283 + 182 * group + offset) =
      sourceHashReplay group (fun i => rows (283 + 182 * group + i)) offset := by
  intro offset
  induction offset using Nat.strong_induction_on with
  | h offset ih =>
    intro bound
    rw [sourceHashReplay_eq]
    by_cases isInitial : offset < 16
    · simp only [if_pos isInitial]
    · simp only [if_neg isInitial, if_pos bound]
      have wireBound : offset - 16 < 166 := by omega
      have rowEq : hashRow group (offset - 16) = 283 + 182 * group + offset := by
        unfold hashRow
        omega
      rw [← rowEq, recurrence _ wireBound]
      obtain ⟨_, _, _, lower, upper⟩ := exact_hash_roots_valid groupBound wireBound
      apply fieldAt_congr_on_span pub (fun _ => 0) rows _
        (283 + 182 * group) (hashRow group (offset - 16))
        (by unfold hashRow; omega) _ _ lower upper
      intro row low high
      rw [if_pos ⟨low, high⟩]
      rw [rowEq] at high
      have smaller : row - (283 + 182 * group) < offset := by omega
      have equality := ih (row - (283 + 182 * group)) smaller (by omega)
      have indexEq : 283 + 182 * group + (row - (283 + 182 * group)) = row := by omega
      simpa only [indexEq] using equality

theorem accepted_hash_trace_refines_source_replay {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {group lane : Nat} (groupBound : group < 2) (laneBound : lane < 64) :
    ∀ offset, offset < 182 → laneField packed lane (283 + 182 * group + offset) =
      sourceHashReplay group
        (fun i => laneField packed lane (283 + 182 * group + i)) offset := by
  exact hash_recurrence_refines_source_replay groupBound
    (fun n => (publicWords.getD n 0 : F)) (laneField packed lane)
    (fun _ bound => accepted_hash_recurrence accepted groupBound bound laneBound)

theorem laneField_eq_packedWord (packed : List Nat) (lane row : Nat) (bound : row < 686) :
    laneField packed lane row = (packedWord packed (row * 64 + lane) : F) := by
  simp [laneField, packedWitnessLaneRows, List.getD_eq_getElem?_getD, bound,
    relationRowCount, packingFactor, packedWord]

/-- Universal per-call source reconstruction covers all 125 live calls and the
three padded calls. This is a source-DAG replay, not yet primitive equality. -/
theorem accepted_hash_call_final_refines_source_replay {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {call limb : Nat} (callBound : call < 128) (limbBound : limb < 16) :
    (packedWord packed
      (Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashFinalIndex call limb) : F) =
      sourceHashReplay (call / 64)
        (fun i => (packedWord packed
          (Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashInitialIndex call i) : F))
        (166 + limb) := by
  have groupBound : call / 64 < 2 := by omega
  have laneBound : call % 64 < 64 := Nat.mod_lt _ (by decide)
  have replay := accepted_hash_trace_refines_source_replay accepted groupBound laneBound
    (166 + limb) (by omega)
  have finalBound : 283 + 182 * (call / 64) + (166 + limb) < 686 := by omega
  rw [laneField_eq_packedWord packed _ _ finalBound] at replay
  have finalIndex : (283 + 182 * (call / 64) + (166 + limb)) * 64 + call % 64 =
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashFinalIndex call limb := by
    simp [Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashFinalIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashFinalRowOffset,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.mul_add,
      Nat.mul_comm, Nat.add_assoc]
  rw [finalIndex] at replay
  have initialEq : ∀ i, i < 16 →
      laneField packed (call % 64) (283 + 182 * (call / 64) + i) =
        (packedWord packed
          (Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashInitialIndex call i) : F) := by
    intro i bound
    rw [laneField_eq_packedWord packed _ _ (by omega)]
    congr 2
    simp [Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashInitialIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowsPerGroup,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.mul_add,
      Nat.mul_comm, Nat.add_assoc]
  have congrReplay : ∀ offset, offset < 182 →
      sourceHashReplay (call / 64)
        (fun i => laneField packed (call % 64) (283 + 182 * (call / 64) + i)) offset =
      sourceHashReplay (call / 64)
        (fun i => (packedWord packed
          (Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashInitialIndex call i) : F))
        offset := by
    intro offset
    induction offset using Nat.strong_induction_on with
    | h offset ih =>
      intro bound
      rw [sourceHashReplay_eq, sourceHashReplay_eq]
      by_cases initial : offset < 16
      · simp only [if_pos initial]
        exact initialEq offset initial
      · simp only [if_neg initial, if_pos bound]
        congr 1
        funext row
        split
        · rename_i within
          exact ih _ (by omega) (by omega)
        · rfl
  exact replay.trans (congrReplay _ (by omega))

end
end HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
