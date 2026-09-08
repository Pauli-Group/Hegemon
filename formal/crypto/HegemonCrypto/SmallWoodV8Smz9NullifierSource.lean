import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition
import HegemonCrypto.SmallWoodV8Smz9NullifierSponge
import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9NullifierSource

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex rawIndex inputNoteCall inputDirectionRow)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9NullifierSponge

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def nullifierCall (input : Nat) : Nat := 36 + 36 * input
def nullifierWords (packed : List Nat) (input : Nat) : List Nat :=
  (List.range 6).map (spongeSourceWord packed (nullifierCall input))
def nullifierFrameTarget (lane : Nat) : Nat :=
  if lane = 8 then 2 else if lane = 9 then 545 else if lane = 10 then 543 else
    if lane = 11 then 1 else if lane = 15 then 544 else 0
def nullifierFrameConstant (lane : Nat) : Nat :=
  if lane = 8 then 2 else if lane = 9 then 6 else if lane = 10 then poseidon2V8SpongeModeMarker else
    if lane = 11 then 1 else if lane = 15 then poseidon2V8SuiteMarker else 0
def nullifierFrameAttempt (input lane : Nat) : CsrExecutableAttempt :=
  attempt (18300 + 16 * input + lane) 19 (16 * input + lane) 0
    [(hashInitialIndex (nullifierCall input) lane, 1)] (nullifierFrameTarget lane)

private theorem csr35_entry_mem_exact {chunk : List CsrExecutableAttempt}
    {entry : CsrExecutableAttempt}
    (chunkMem : chunk ∈ V8Smz9ProgramCanonicalityCsr35.chunkList)
    (entryMem : entry ∈ chunk) : entry ∈ exactCsrAttempts := by
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  apply List.mem_flatten_of_mem _ entryMem
  unfold V8Smz9ProgramCanonicalityGenerated.csrChunks000
    V8Smz9ProgramCanonicalityGenerated.csrChunks001
    V8Smz9ProgramCanonicalityGenerated.csrChunks002
    V8Smz9ProgramCanonicalityGenerated.csrChunks003
    V8Smz9ProgramCanonicalityGenerated.csrChunks004
    V8Smz9ProgramCanonicalityGenerated.csrChunks005
    V8Smz9ProgramCanonicalityGenerated.csrChunks006
    V8Smz9ProgramCanonicalityGenerated.csrChunks007
    V8Smz9ProgramCanonicalityGenerated.csrChunks008
    V8Smz9ProgramCanonicalityGenerated.csrChunks009
    V8Smz9ProgramCanonicalityGenerated.csrChunks010
    V8Smz9ProgramCanonicalityGenerated.csrChunks011
    V8Smz9ProgramCanonicalityGenerated.csrChunks012
    V8Smz9ProgramCanonicalityGenerated.csrChunks013
    V8Smz9ProgramCanonicalityGenerated.csrChunks014
    V8Smz9ProgramCanonicalityGenerated.csrChunks015
    V8Smz9ProgramCanonicalityGenerated.csrChunks016
    V8Smz9ProgramCanonicalityGenerated.csrChunks017
    V8Smz9ProgramCanonicalityGenerated.csrChunks018
    V8Smz9ProgramCanonicalityGenerated.csrChunks019
    V8Smz9ProgramCanonicalityGenerated.csrChunks020
    V8Smz9ProgramCanonicalityGenerated.csrChunks021
    V8Smz9ProgramCanonicalityGenerated.csrChunks022
    V8Smz9ProgramCanonicalityGenerated.csrChunks023
    V8Smz9ProgramCanonicalityGenerated.csrChunks024
    V8Smz9ProgramCanonicalityGenerated.csrChunks025
    V8Smz9ProgramCanonicalityGenerated.csrChunks026
    V8Smz9ProgramCanonicalityGenerated.csrChunks027
    V8Smz9ProgramCanonicalityGenerated.csrChunks028
    V8Smz9ProgramCanonicalityGenerated.csrChunks029
    V8Smz9ProgramCanonicalityGenerated.csrChunks030
    V8Smz9ProgramCanonicalityGenerated.csrChunks031
    V8Smz9ProgramCanonicalityGenerated.csrChunks032
    V8Smz9ProgramCanonicalityGenerated.csrChunks033
    V8Smz9ProgramCanonicalityGenerated.csrChunks034
    V8Smz9ProgramCanonicalityGenerated.csrChunks035
  simp only [List.mem_append]
  aesop

theorem exact_nullifier_frame_attempts (input : Fin 2) (lane : Fin 16)
    (capacity : 6 ≤ lane.val) : nullifierFrameAttempt input.val lane.val ∈ exactCsrAttempts := by
  have checked : ∀ input : Fin 2, ∀ lane : Fin 16, 6 ≤ lane.val →
      nullifierFrameAttempt input.val lane.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk012 := by decide
  exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList])
    (checked input lane capacity)

theorem exact_nullifier_frame_nodes : ∀ lane : Fin 16,
    exactCsrExpressions[nullifierFrameTarget lane.val]? =
      some (.constant (nullifierFrameConstant lane.val)) := by decide

theorem nullifier_frame_constant_canonical (lane : Nat) :
    nullifierFrameConstant lane < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  unfold nullifierFrameConstant
  split_ifs <;> decide

theorem accepted_nullifier_frame_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (input : Fin 2) (lane : Fin 16) (capacity : 6 ≤ lane.val) :
    packedWord packed (hashInitialIndex (nullifierCall input.val) lane.val) =
      nullifierFrameConstant lane.val := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have constant : (values.getD (nullifierFrameTarget lane.val) 0 : F) =
      (nullifierFrameConstant lane.val : F) := by
    simpa only [expressionField] using equations _ _ (exact_nullifier_frame_nodes lane)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_nullifier_frame_attempts input lane capacity))
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (nullifier_frame_constant_canonical _)
  simpa only [nullifierFrameAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, constant, one_mul, add_zero, packedWord] using equation

theorem nullifier_words_getD (packed : List Nat) (input : Nat) {word : Nat} (bound : word < 6) :
    (nullifierWords packed input).getD word 0 = spongeSourceWord packed (nullifierCall input) word := by
  simp [nullifierWords, List.getD_eq_getElem?_getD, bound]

theorem accepted_nullifier_initial_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (input : Fin 2) :
    packedInitialState packed (nullifierCall input.val) = nullifierFrame (nullifierWords packed input.val) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  by_cases rate : lane < 6
  · change _ = (if lane < 6 then Poseidon2Width16Kernel.fieldAdd 0
      ((nullifierWords packed input.val).getD lane 0) else _)
    rw [if_pos rate, nullifier_words_getD packed input.val rate]
    have sourceBound := sponge_source_word_canonical accepted.2.1 (nullifierCall input.val) lane
    have block : lane / 8 = 0 := Nat.div_eq_of_lt (by omega)
    have index : lane % 8 = lane := Nat.mod_eq_of_lt (by omega)
    simp only [Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
    change _ = spongeSourceWord packed (nullifierCall input.val) lane % 18446744069414584321
    have canonical : spongeSourceWord packed (nullifierCall input.val) lane < 18446744069414584321 := sourceBound
    rw [Nat.mod_eq_of_lt canonical]
    simp only [spongeSourceWord, block, index, ↓reduceIte, Nat.add_zero]
  · change _ = (if lane < 6 then _ else _)
    rw [if_neg rate]
    exact accepted_nullifier_frame_coordinate accepted input ⟨lane, laneBound⟩
      (show 6 ≤ lane from by omega)

/-- The accepted six-word hash is the existing semantic nullifier function;
the raw scalar and note-source bindings are refined in the following lemmas. -/
theorem accepted_nullifier_digest_exact_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (input : Fin 2) :
    (packedFinalState packed (nullifierCall input.val)).take digestWords =
      exactV8Nullifier input.val (spongeSourceWord packed (nullifierCall input.val) 0)
        (spongeSourceWord packed (nullifierCall input.val) 1)
        ((List.range 4).map (fun limb => spongeSourceWord packed (nullifierCall input.val) (2 + limb))) := by
  have callBound : nullifierCall input.val < 128 := by
    have := input.isLt
    unfold nullifierCall
    omega
  rw [accepted_final_state_eq_kernel accepted callBound, accepted_nullifier_initial_frame accepted input]
  change _ = poseidon2V8Sponge poseidon2V8NullifierDomain (nullifierWords packed input.val)
  exact (nullifier_sponge_one_frame _ (by simp [nullifierWords])).symm

theorem nullifier_trace_basic {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions) :
    (values.getD 0 0 : F) = 0 ∧ (values.getD 1 0 : F) = 1 ∧
      (values.getD 158 0 : F) = -1 ∧ (values.getD 265 0 : F) = 1 := by
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zero, one, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have positive : (values.getD 265 0 : F) = 1 := by
    simpa only [expressionField, zero, negative, zero_sub, neg_neg] using
      equations 265 (.sub 0 158) (by decide)
  exact ⟨zero, one, negative, positive⟩

def nullifierScalarAttempt (input : Nat) : CsrExecutableAttempt :=
  attempt (18300 + 16 * input) 19 (16 * input) 0
    [(hashInitialIndex (nullifierCall input) 0, 1), (rawIndex (95 + input), 158)] 0

theorem exact_nullifier_scalar_attempts (input : Fin 2) :
    nullifierScalarAttempt input.val ∈ exactCsrAttempts := by
  have checked : ∀ input : Fin 2,
      nullifierScalarAttempt input.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk011 ∨
      nullifierScalarAttempt input.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk012 := by decide
  rcases checked input with first | second
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) first
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) second

/-- The mode-dependent effective scalar is the actual raw95/96 coordinate.
Its identification with authorization hash outputs is a separate source proof. -/
theorem accepted_nullifier_scalar_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (input : Fin 2) :
    spongeSourceWord packed (nullifierCall input.val) 0 = packedWord packed (rawIndex (95 + input.val)) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨zero, one, negative, positive⟩ := nullifier_trace_basic equations
  have equation := accepted_csr_attempt_field_equality (attempts _ (exact_nullifier_scalar_attempts input))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _)
  simp only [nullifierScalarAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, one, negative, zero, one_mul, neg_one_mul, add_zero] at equation
  simp only [spongeSourceWord, Nat.zero_div, Nat.zero_mod, Nat.add_zero, ↓reduceIte, packedWord]
  linear_combination equation

def nullifierRhoAttempt (input limb : Nat) : CsrExecutableAttempt :=
  attempt (18302 + 16 * input + limb) 19 (16 * input + 2 + limb) 0
    ([(hashInitialIndex (nullifierCall input) (2 + limb), 1),
      (hashInitialIndex (inputNoteCall input + (6 + limb) / 8) ((6 + limb) % 8), 158)] ++
      if limb < 2 then [] else [(hashFinalIndex (inputNoteCall input) (limb - 2), 265)]) 0

theorem exact_nullifier_rho_attempts (input : Fin 2) (limb : Fin 4) :
    nullifierRhoAttempt input.val limb.val ∈ exactCsrAttempts := by
  have checked : ∀ input : Fin 2, ∀ limb : Fin 4,
      nullifierRhoAttempt input.val limb.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk011 ∨
      nullifierRhoAttempt input.val limb.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk012 := by decide
  rcases checked input limb with first | second
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) first
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) second

theorem accepted_nullifier_rho_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 4) :
    spongeSourceWord packed (nullifierCall input.val) (2 + limb.val) =
      spongeSourceWord packed (inputNoteCall input.val) (6 + limb.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨zero, one, negative, positive⟩ := nullifier_trace_basic equations
  have equation := accepted_csr_attempt_field_equality (attempts _ (exact_nullifier_rho_attempts input limb))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _)
    (sponge_source_word_canonical accepted.2.1 _ _)
  have small : (2 + limb.val) / 8 = 0 := Nat.div_eq_of_lt (by have := limb.isLt; omega)
  have smallMod : (2 + limb.val) % 8 = 2 + limb.val := Nat.mod_eq_of_lt (by have := limb.isLt; omega)
  by_cases first : limb.val < 2
  · have block : (6 + limb.val) / 8 = 0 := Nat.div_eq_of_lt (by omega)
    simp only [nullifierRhoAttempt, attempt, first, ↓reduceIte, List.append_nil,
      csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      one, negative, zero, one_mul, neg_one_mul, add_zero, block] at equation
    simp only [spongeSourceWord, small, smallMod, block, ↓reduceIte, Nat.add_zero, packedWord]
    linear_combination equation
  · have block : (6 + limb.val) / 8 = 1 := by have := limb.isLt; omega
    have remainder : (6 + limb.val) % 8 = limb.val - 2 := by have := limb.isLt; omega
    have previous : inputNoteCall input.val + 1 - 1 = inputNoteCall input.val := by omega
    simp only [nullifierRhoAttempt, attempt, first, ↓reduceIte, List.cons_append, List.nil_append,
      csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      one, negative, positive, zero, one_mul, neg_one_mul, add_zero, block, remainder] at equation
    simp only [spongeSourceWord, small, smallMod, block, remainder, Nat.one_ne_zero,
      ↓reduceIte, Nat.add_zero, previous]
    rw [field_sub_cast _ _ (by
      have canonical := packed_word_canonical accepted.2.1 (hashFinalIndex (inputNoteCall input.val) (limb.val - 2))
      change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at canonical
      omega)]
    simp only [packedWord]
    linear_combination equation

theorem accepted_nullifier_rho_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (input : Fin 2) :
    (List.range 4).map (fun limb => spongeSourceWord packed (nullifierCall input.val) (2 + limb)) =
      (projectNote packed (inputNoteCall input.val)).rho := by
  simp only [projectNote]
  apply List.map_congr_left
  intro limb member
  exact accepted_nullifier_rho_word accepted input ⟨limb, List.mem_range.mp member⟩

def positionPositiveRoot (bit : Nat) : Nat :=
  if bit = 0 then 1 else if bit = 1 then 2 else if bit = 2 then 128 else 201 + 2 * bit
def positionNegativeRoot (bit : Nat) : Nat :=
  if bit = 0 then 158 else if bit = 1 then 206 else if bit = 2 then 159 else 202 + 2 * bit
def nullifierPositionTerms (input : Nat) : List (Nat × Nat) :=
  (List.range 32).map (fun bit => (rawIndex (inputDirectionRow input bit), positionNegativeRoot bit))
def nullifierPositionAttempt (input : Nat) : CsrExecutableAttempt :=
  attempt (18301 + 16 * input) 19 (16 * input + 1) 0
    ((hashInitialIndex (nullifierCall input) 1, 1) :: nullifierPositionTerms input) 0

theorem exact_position_coefficient_nodes : ∀ bit : Fin 32,
    exactCsrExpressions[positionPositiveRoot bit.val]? = some (.constant (2 ^ bit.val)) ∧
    exactCsrExpressions[positionNegativeRoot bit.val]? = some (.sub 0 (positionPositiveRoot bit.val)) := by
  decide

theorem exact_nullifier_position_attempts (input : Fin 2) :
    nullifierPositionAttempt input.val ∈ exactCsrAttempts := by
  have checked : ∀ input : Fin 2,
      nullifierPositionAttempt input.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk011 ∨
      nullifierPositionAttempt input.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk012 := by decide
  rcases checked input with first | second
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) first
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) second

theorem position_coefficient_value {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions) (bit : Fin 32) :
    (values.getD (positionNegativeRoot bit.val) 0 : F) = -((2 ^ bit.val : Nat) : F) := by
  have zero := (nullifier_trace_basic equations).1
  have nodes := exact_position_coefficient_nodes bit
  have positive : (values.getD (positionPositiveRoot bit.val) 0 : F) = ((2 ^ bit.val : Nat) : F) := by
    simpa only [expressionField] using equations _ _ nodes.1
  simpa only [expressionField, zero, positive, zero_sub] using equations _ _ nodes.2

theorem nullifier_position_field_sum {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (packed : List Nat) (input : Nat) :
    csrFieldSum values packed (nullifierPositionTerms input) = -(projectPosition packed input : F) := by
  have mapped : (List.range 32).map (fun bit =>
      (values.getD (positionNegativeRoot bit) 0 : F) *
        (packed.getD (rawIndex (inputDirectionRow input bit)) 0 : F)) =
      ((List.range 32).map (fun bit => 2 ^ bit * directionWord packed input bit)).map
        (fun (value : Nat) => -(value : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro bit member
    rw [position_coefficient_value equations ⟨bit, List.mem_range.mp member⟩]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul, directionWord, packedWord]
  unfold csrFieldSum nullifierPositionTerms
  rw [List.map_map]
  change ((List.range 32).map (fun bit =>
      (values.getD (positionNegativeRoot bit) 0 : F) *
        (packed.getD (rawIndex (inputDirectionRow input bit)) 0 : F))).sum = _
  rw [mapped, sum_neg_cast]
  rfl

theorem accepted_nullifier_position_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (input : Fin 2) :
    spongeSourceWord packed (nullifierCall input.val) 1 = projectPosition packed input.val := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨zero, one, negative, positive⟩ := nullifier_trace_basic equations
  have equation := accepted_csr_attempt_field_equality (attempts _ (exact_nullifier_position_attempts input))
  have positionBound : projectPosition packed input.val <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus :=
    lt_trans (accepted_project_position_bound accepted input.isLt) (by decide)
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _) positionBound
  simp only [nullifierPositionAttempt, attempt, csr_field_sum_cons,
    nullifier_position_field_sum equations, zero, one, one_mul] at equation
  simp only [spongeSourceWord, Nat.reduceDiv, Nat.reduceMod, Nat.add_zero, ↓reduceIte, packedWord]
  linear_combination equation

/-- Both input nullifiers use the actual decoded note rho and the exact
32-bit decoded position. Only the mode-dependent raw95/96 scalar remains to
be identified with the separately checked authorization hash output. -/
theorem accepted_nullifier_digest_exact_decoded {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (input : Fin 2) :
    (packedFinalState packed (nullifierCall input.val)).take digestWords =
      exactV8Nullifier input.val (packedWord packed (rawIndex (95 + input.val)))
        (projectPosition packed input.val) (projectNote packed (inputNoteCall input.val)).rho := by
  rw [accepted_nullifier_digest_exact_source accepted input,
    accepted_nullifier_scalar_source accepted input, accepted_nullifier_position_source accepted input,
    accepted_nullifier_rho_source accepted input]

def publicNullifierAttempt (input limb : Nat) : CsrExecutableAttempt :=
  attempt (18332 + 7 * input + limb) 20 (7 * input + limb) 1
    [(hashFinalIndex (nullifierCall input) limb, 4 + input)] (266 + 15 * input + limb)

theorem exact_public_nullifier_attempts (input : Fin 2) (limb : Fin 7) :
    publicNullifierAttempt input.val limb.val ∈ exactCsrAttempts := by
  have checked : ∀ input : Fin 2, ∀ limb : Fin 7,
      publicNullifierAttempt input.val limb.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk012 ∨
      publicNullifierAttempt input.val limb.val ∈ V8Smz9ProgramCanonicalityCsr35.chunk013 := by decide
  rcases checked input limb with first | second
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) first
  · exact csr35_entry_mem_exact (by simp [V8Smz9ProgramCanonicalityCsr35.chunkList]) second

theorem exact_public_nullifier_nodes : ∀ input : Fin 2, ∀ limb : Fin 7,
    exactCsrExpressions[4 + input.val]? = some (.publicWord input.val) ∧
    exactCsrExpressions[8 + 7 * input.val + limb.val]? =
      some (.publicWord (4 + 7 * input.val + limb.val)) ∧
    exactCsrExpressions[266 + 15 * input.val + limb.val]? =
      some (.mul (4 + input.val) (8 + 7 * input.val + limb.val)) := by decide

theorem accepted_active_public_nullifier_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (input : Fin 2) (limb : Fin 7) (active : publicWords.getD input.val 0 = 1) :
    packedWord packed (hashFinalIndex (nullifierCall input.val) limb.val) =
      publicWords.getD (4 + 7 * input.val + limb.val) 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have nodes := exact_public_nullifier_nodes input limb
  have flagValue : (values.getD (4 + input.val) 0 : F) = 1 := by
    simpa only [expressionField, active, Nat.cast_one] using equations _ _ nodes.1
  have publicValue : (values.getD (8 + 7 * input.val + limb.val) 0 : F) =
      (publicWords.getD (4 + 7 * input.val + limb.val) 0 : F) := by
    simpa only [expressionField] using equations _ _ nodes.2.1
  have targetValue : (values.getD (266 + 15 * input.val + limb.val) 0 : F) =
      (publicWords.getD (4 + 7 * input.val + limb.val) 0 : F) := by
    simpa only [expressionField, flagValue, publicValue, one_mul] using equations _ _ nodes.2.2
  have equation := accepted_csr_attempt_field_equality (attempts _ (exact_public_nullifier_attempts input limb))
  have publicBound := (canonical_public_coordinate accepted.1
    (index := 4 + 7 * input.val + limb.val) (by
      have := input.isLt; have := limb.isLt; change _ < 120; omega)).2
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) publicBound
  simpa only [publicNullifierAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, flagValue, targetValue, one_mul, add_zero, packedWord] using equation

theorem accepted_active_nullifier_exact_decoded {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (input : Fin 2)
    (active : publicWords.getD input.val 0 = 1) :
    exactV8Nullifier input.val (packedWord packed (rawIndex (95 + input.val)))
      (projectPosition packed input.val) (projectNote packed (inputNoteCall input.val)).rho =
        (List.range 7).map (fun limb => publicWords.getD (4 + 7 * input.val + limb) 0) := by
  rw [← accepted_nullifier_digest_exact_decoded accepted input]
  apply List.ext_getElem
  · simp [packedFinalState, digestWords]
  · intro limb leftBound rightBound
    have limbBound : limb < 7 := by simpa using rightBound
    simp only [packedFinalState, List.getElem_take, List.getElem_map, List.getElem_range]
    exact accepted_active_public_nullifier_word accepted input ⟨limb, limbBound⟩ active

theorem encoded_public_nullifier_word (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    (input : Fin 2) (limb : Fin 7) :
    (encodePublicStatement statement).getD (4 + 7 * input.val + limb.val) 0 =
      (digestAt statement.nullifiers input.val).getD limb.val 0 := by
  obtain ⟨inputLength, outputLength, nullifierFlatLength, commitmentFlatLength,
    ciphertextFlatLength, rootLength, assetLength⟩ := admitted_public_lengths statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags
  have prefixLength : publicPrefix.length = 4 := by simp [publicPrefix, inputLength, outputLength]
  have encoded : encodePublicStatement statement = publicPrefix ++
      (statement.nullifiers.flatten ++ (statement.commitments.flatten ++
        statement.ciphertextCommitments.flatten ++
          [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++
          statement.merkleRoot ++ statement.balanceAssets ++ encodeCompatibility statement.compatibility ++
          [statement.version, statement.cryptoSuite] ++ encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  have offset : 4 + 7 * input.val + limb.val - 4 = 7 * input.val + limb.val := by omega
  rw [offset, List.getD_append _ _ _ _ (by have := input.isLt; have := limb.isLt; omega)]
  obtain ⟨_, _, _, _, nullifierCount, nullifierWords, _⟩ := canonical
  obtain ⟨first, second, chunks⟩ := List.length_eq_two.mp nullifierCount
  have firstLength : first.length = 7 := (nullifierWords first (by simp [chunks])).1
  fin_cases input
  · simpa [chunks, digestAt] using List.getD_append first second 0 limb.val (by have := limb.isLt; omega)
  · simpa [chunks, digestAt, firstLength] using List.getD_append_right first second 0 (7 + limb.val) (by omega)

theorem admitted_public_nullifier_digest {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) (input : Fin 2) :
    (List.range 7).map (fun limb => publicWords.getD (4 + 7 * input.val + limb) 0) =
      digestAt statement.nullifiers input.val := by
  obtain ⟨_, _, _, _, nullifierCount, nullifierWords, _⟩ := domain.2.1
  have inputBound : input.val < statement.nullifiers.length := by rw [nullifierCount]; exact input.isLt
  have found : statement.nullifiers[input.val]? = some (digestAt statement.nullifiers input.val) := by
    simp [digestAt, List.getD, inputBound]
  have digestLength : (digestAt statement.nullifiers input.val).length = 7 :=
    (nullifierWords _ (List.mem_of_getElem? found)).1
  apply List.ext_getElem (by simp [digestLength])
  intro limb leftBound rightBound
  have limbBound : limb < 7 := by simpa using leftBound
  simp only [List.getElem_map, List.getElem_range]
  rw [← domain.1, encoded_public_nullifier_word statement domain.2.1 input ⟨limb, limbBound⟩]
  exact List.getD_eq_getElem _ _ rightBound

/-- Public admission and arbitrary packed acceptance bind both input
nullifiers to the exact six-word semantic hash of the decoded position/rho
and the actual effective-scalar coordinate95/96. -/
theorem admitted_packed_project_typed_nullifiers_raw_scalar {statement : V8PublicStatement}
    {publicWords packed : List Nat} (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    ∀ slot, slot < inputCount → flagAt statement.inputFlags slot = 1 →
      exactV8Nullifier slot (packedWord packed (rawIndex (95 + slot)))
        ((projectTypedWitness statement packed).inputs.getD slot default).position
        ((projectTypedWitness statement packed).inputs.getD slot default).note.rho =
          digestAt statement.nullifiers slot := by
  intro slot bound active
  have rawActive : publicWords.getD slot 0 = 1 := by
    rw [← domain.1, encoded_input_flag statement domain.2.1 bound]
    exact active
  rw [project_typed_input_at statement packed default bound]
  change exactV8Nullifier slot (packedWord packed (rawIndex (95 + slot)))
    (projectPosition packed slot) (projectNote packed (inputNoteCall slot)).rho = _
  exact (accepted_active_nullifier_exact_decoded domain.2.2 ⟨slot, bound⟩ rawActive).trans
    (admitted_public_nullifier_digest domain ⟨slot, bound⟩)


end HegemonCrypto.SmallWood.V8Smz9NullifierSource
