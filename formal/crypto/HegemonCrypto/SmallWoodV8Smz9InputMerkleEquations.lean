import HegemonCrypto.SmallWoodV8Smz9InputMerkleSources
import HegemonCrypto.SmallWoodV8Smz9NullifierSource

namespace HegemonCrypto.SmallWood.V8Smz9InputMerkleEquations

open Hegemon.Transaction hiding Digest
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt FieldExpression)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex inputMerkleCall inputNoteCall inputDirectionRow)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9NullifierSource (nullifier_trace_basic)
open HegemonCrypto.SmallWood.V8Smz9InputMerkleSources

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

theorem accepted_initial_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step lane : Nat} (stepBound : step < 64) (laneBound : lane < 14) :
    packedWord packed (hashInitialIndex (merkleCall step) lane) =
      packedWord packed (inlineIndex step (lane % 7) (if lane < 7 then 1 else 2)) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨zero, one, negative, _⟩ := nullifier_trace_basic equations
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_initial_attempt (offset := step * 16 + lane) (by omega)))
  have div : (step * 16 + lane) / 16 = step := by omega
  have mod : (step * 16 + lane) % 16 = lane := by omega
  simp only [initialAttempt, div, mod, laneBound, if_true, List.cons_append,
    List.nil_append, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, negative, zero, one_mul, neg_one_mul,
    add_zero] at equation
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _)
  simp only [packedWord]
  linear_combination equation

theorem accepted_initial_capacity {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step lane : Nat} (stepBound : step < 64) (laneBound : lane < 16)
    (capacity : 14 ≤ lane) :
    packedWord packed (hashInitialIndex (merkleCall step) lane) =
      if lane = 14 then poseidon2V8MerkleDomain else poseidon2V8SuiteMarker := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨zero, one, negative, _⟩ := nullifier_trace_basic equations
  have domain : (values.getD 128 0 : F) = (poseidon2V8MerkleDomain : F) := by
    simpa only [expressionField, poseidon2V8MerkleDomain] using
      equations 128 (.constant 4) (by decide)
  have marker : (values.getD 544 0 : F) = (poseidon2V8SuiteMarker : F) := by
    simpa only [expressionField, poseidon2V8SuiteMarker] using
      equations 544 (.constant poseidon2V8SuiteMarker) (by decide)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_initial_attempt (offset := step * 16 + lane) (by omega)))
  have div : (step * 16 + lane) / 16 = step := by omega
  have mod : (step * 16 + lane) % 16 = lane := by omega
  have notRate : ¬lane < 14 := by omega
  simp only [initialAttempt, div, mod, notRate, if_false, List.append_nil,
    attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    one, one_mul, add_zero] at equation
  by_cases first : lane = 14
  · rw [if_pos first] at equation ⊢
    apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
    exact equation.trans domain
  · rw [if_neg first] at equation ⊢
    apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
    exact equation.trans marker

theorem accepted_current_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step limb : Nat} (stepBound : step < 64) (limbBound : limb < 7) :
    packedWord packed (inlineIndex step limb 0) =
      packedWord packed (hashFinalIndex (previousCall step) limb) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨zero, one, negative, _⟩ := nullifier_trace_basic equations
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_current_attempt (offset := step * 7 + limb) (by omega)))
  have div : (step * 7 + limb) / 7 = step := by omega
  have mod : (step * 7 + limb) % 7 = limb := by omega
  simp only [currentAttempt, div, mod, attempt, csrFieldSum, List.map_cons,
    List.map_nil, List.sum_cons, List.sum_nil, one, negative, zero, one_mul,
    neg_one_mul, add_zero] at equation
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _)
  simp only [packedWord]
  linear_combination equation

theorem accepted_direction_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step limb : Nat} (stepBound : step < 64) (limbBound : limb < 7) :
    packedWord packed (inlineIndex step limb 3) =
      directionWord packed (step / 32) (step % 32) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨zero, one, negative, _⟩ := nullifier_trace_basic equations
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_direction_attempt (offset := step * 7 + limb) (by omega)))
  have div : (step * 7 + limb) / 7 = step := by omega
  have mod : (step * 7 + limb) % 7 = limb := by omega
  simp only [directionAttempt, div, mod, attempt, csrFieldSum, List.map_cons,
    List.map_nil, List.sum_cons, List.sum_nil, one, negative, zero, one_mul,
    neg_one_mul, add_zero] at equation
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _)
  simp only [packedWord]
  linear_combination equation

theorem orientation_nodes : ∀ group : Fin 7,
    exactNonlinearExpressions[1204 + 4 * group.val]? =
      some (.sub (378 + 4 * group.val) (377 + 4 * group.val)) ∧
    exactNonlinearExpressions[1205 + 4 * group.val]? =
      some (.mul (379 + 4 * group.val) (1204 + 4 * group.val)) ∧
    exactNonlinearExpressions[1206 + 4 * group.val]? =
      some (.add (377 + 4 * group.val) (1205 + 4 * group.val)) ∧
    exactNonlinearExpressions[1207 + 4 * group.val]? =
      some (.sub (376 + 4 * group.val) (1206 + 4 * group.val)) ∧
    1207 + 4 * group.val ∈ exactNonlinearRoots := by decide

theorem orientation_row_nodes : ∀ group : Fin 7, ∀ component : Fin 4,
    exactNonlinearExpressions[376 + 4 * group.val + component.val]? =
      some (.witnessRow (252 + 4 * group.val + component.val)) := by decide

theorem accepted_orientation_field {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step limb : Nat} (stepBound : step < 64) (limbBound : limb < 7) :
    (packedWord packed (inlineIndex step limb 0) : F) =
      (packedWord packed (inlineIndex step limb 1) : F) +
        (packedWord packed (inlineIndex step limb 3) : F) *
        ((packedWord packed (inlineIndex step limb 2) : F) -
          (packedWord packed (inlineIndex step limb 1) : F)) := by
  let group := (step * 7 + limb) / 64
  let lane := (step * 7 + limb) % 64
  have groupBound : group < 7 := by dsimp [group]; omega
  have laneBound : lane < 64 := Nat.mod_lt _ (by decide)
  obtain ⟨differenceNode, productNode, sumNode, rootNode, member⟩ :=
    orientation_nodes ⟨group, groupBound⟩
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted laneBound member
  have row : ∀ component : Fin 4,
      (values.getD (376 + 4 * group + component.val) 0 : F) =
      (packedWord packed (inlineIndex step limb component.val) : F) := by
    intro component
    have equation := equations _ _ (orientation_row_nodes ⟨group, groupBound⟩ component)
    have rowBound : 252 + 4 * group + component.val <
        Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount := by
      change _ < 686
      have := component.isLt
      omega
    simpa [expressionField, Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows,
      List.getD_eq_getElem?_getD, rowBound,
      Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor,
      packedWord, inlineIndex, group, lane] using equation
  have current := row ⟨0, by decide⟩
  have left := row ⟨1, by decide⟩
  have right := row ⟨2, by decide⟩
  have direction := row ⟨3, by decide⟩
  have difference := equations _ _ differenceNode
  have product := equations _ _ productNode
  have sum := equations _ _ sumNode
  have root := equations _ _ rootNode
  simp only [expressionField] at difference product sum root
  have leftIndex : 376 + 4 * group + 1 = 377 + 4 * group := by omega
  have rightIndex : 376 + 4 * group + 2 = 378 + 4 * group := by omega
  have directionIndex : 376 + 4 * group + 3 = 379 + 4 * group := by omega
  simp only [Nat.add_zero] at current
  rw [leftIndex] at left
  rw [rightIndex] at right
  rw [directionIndex] at direction
  rw [sum, product, difference, current, left, right, direction] at root
  exact sub_eq_zero.mp (root.symm.trans rootZero)

theorem accepted_selected_current {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {step limb : Nat} (stepBound : step < 64) (limbBound : limb < 7) :
    packedWord packed (inlineIndex step limb 0) =
      packedWord packed (inlineIndex step limb
        (if directionWord packed (step / 32) (step % 32) = 0 then 1 else 2)) := by
  have equation := accepted_orientation_field accepted stepBound limbBound
  rw [accepted_direction_source accepted stepBound limbBound] at equation
  rcases accepted_direction_boolean accepted (input := step / 32) (bit := step % 32)
    (by omega) (Nat.mod_lt _ (by decide)) with zero | one
  · rw [zero, Nat.cast_zero, zero_mul, add_zero] at equation
    rw [if_pos zero]
    exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
      (packed_word_canonical accepted.2.1 _) equation
  · rw [one, Nat.cast_one, one_mul] at equation
    rw [if_neg (by omega)]
    apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
      (packed_word_canonical accepted.2.1 _)
    linear_combination equation


end HegemonCrypto.SmallWood.V8Smz9InputMerkleEquations
