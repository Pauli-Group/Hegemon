import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition
import HegemonCrypto.SmallWoodV8Smz9AccumulatorSponge
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9AccumulatorSource

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt fieldAdd)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9AccumulatorSponge

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def accumulatorCall (which : Nat) : Nat := 98 + 3 * which
def accumulatorWords (packed : List Nat) (which : Nat) : List Nat :=
  (List.range 23).map (spongeSourceWord packed (accumulatorCall which))

def accumulatorFrameTarget (block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then 545 else if lane = 9 then 549 else if lane = 10 then 543 else
      if lane = 15 then 544 else 0
  else if block = 2 ∧ lane = 11 then 1 else 0
def accumulatorFrameConstant (block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then 6 else if lane = 9 then 23 else if lane = 10 then poseidon2V8SpongeModeMarker else
      if lane = 15 then poseidon2V8SuiteMarker else 0
  else if block = 2 ∧ lane = 11 then 1 else 0
def accumulatorFrameAttempt (which block lane : Nat) : CsrExecutableAttempt :=
  let call := accumulatorCall which + block
  attempt (18971 + 55 * which + 16 * block + lane) (29 + 2 * which) (16 * block + lane) 0
    ([(hashInitialIndex call lane, 1)] ++
      if block = 0 then [] else [(hashFinalIndex (call - 1) lane, 158)])
    (accumulatorFrameTarget block lane)

def accumulatorFrameChunks : List (List CsrExecutableAttempt) :=
  [V8Smz9ProgramCanonicalityCsr37.chunk000, V8Smz9ProgramCanonicalityCsr37.chunk001,
    V8Smz9ProgramCanonicalityCsr37.chunk002, V8Smz9ProgramCanonicalityCsr37.chunk003,
    V8Smz9ProgramCanonicalityCsr37.chunk004]

theorem accumulator_frame_chunk_mem_exact {chunk : List CsrExecutableAttempt}
    (member : chunk ∈ accumulatorFrameChunks) :
    chunk ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  have inSection : chunk ∈ V8Smz9ProgramCanonicalityCsr37.chunkList := by
    simp only [accumulatorFrameChunks, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl <;>
      simp [V8Smz9ProgramCanonicalityCsr37.chunkList]
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
    V8Smz9ProgramCanonicalityGenerated.csrChunks036
    V8Smz9ProgramCanonicalityGenerated.csrChunks037
  simp only [List.mem_append]
  aesop

def accumulatorFrameFilter (entry : CsrExecutableAttempt) : Bool :=
  (entry.family == 29 || entry.family == 31) &&
    (8 ≤ entry.localIndex % 16 || entry.localIndex == 39)
def accumulatorFrameSources : List CsrExecutableAttempt :=
  (List.range 2).flatMap fun which => (List.range 3).flatMap fun block =>
    (List.range (if block = 2 then 9 else 8)).map fun lane =>
      accumulatorFrameAttempt which block ((if block = 2 then 7 else 8) + lane)

theorem exact_accumulator_frame_filter :
    accumulatorFrameChunks.flatten.filter accumulatorFrameFilter = accumulatorFrameSources := by decide

theorem exact_accumulator_frame_attempts (which : Fin 2) (block : Fin 3) (lane : Fin 16)
    (coordinate : 8 ≤ lane.val ∨ block.val = 2 ∧ lane.val = 7) :
    accumulatorFrameAttempt which.val block.val lane.val ∈ exactCsrAttempts := by
  have filtered : accumulatorFrameAttempt which.val block.val lane.val ∈
      accumulatorFrameChunks.flatten.filter accumulatorFrameFilter := by
    rw [exact_accumulator_frame_filter]
    apply List.mem_flatMap.mpr
    refine ⟨which.val, List.mem_range.mpr which.isLt, List.mem_flatMap.mpr ?_⟩
    refine ⟨block.val, List.mem_range.mpr block.isLt, List.mem_map.mpr ?_⟩
    by_cases last : block.val = 2
    · refine ⟨lane.val - 7, List.mem_range.mpr ?_, ?_⟩
      · simp only [if_pos last]; have := lane.isLt; omega
      · simp only [if_pos last]; congr 1; omega
    · refine ⟨lane.val - 8, List.mem_range.mpr ?_, ?_⟩
      · simp only [if_neg last]; have := lane.isLt; omega
      · simp only [if_neg last]; congr 1; omega
  obtain ⟨chunk, chunkMember, entryMember⟩ := List.mem_flatten.mp (List.mem_filter.mp filtered).1
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, accumulator_frame_chunk_mem_exact chunkMember, entryMember⟩

theorem exact_accumulator_frame_nodes (block lane : Nat) :
    exactCsrExpressions[accumulatorFrameTarget block lane]? =
      some (.constant (accumulatorFrameConstant block lane)) := by
  unfold accumulatorFrameTarget accumulatorFrameConstant
  split_ifs <;> decide

theorem accumulator_frame_constant_canonical (block lane : Nat) :
    accumulatorFrameConstant block lane < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  unfold accumulatorFrameConstant
  split_ifs <;> decide

theorem accepted_accumulator_frame_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (which : Fin 2) (block : Fin 3) (lane : Fin 16)
    (coordinate : 8 ≤ lane.val ∨ block.val = 2 ∧ lane.val = 7) :
    packedWord packed (hashInitialIndex (accumulatorCall which.val + block.val) lane.val) =
      if block.val = 0 then accumulatorFrameConstant block.val lane.val else
        fieldAdd (packedWord packed (hashFinalIndex (accumulatorCall which.val + block.val - 1) lane.val))
          (accumulatorFrameConstant block.val lane.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zero, one, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have targetValue : (values.getD (accumulatorFrameTarget block.val lane.val) 0 : F) =
      (accumulatorFrameConstant block.val lane.val : F) := by
    simpa only [expressionField] using equations _ _ (exact_accumulator_frame_nodes _ _)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_accumulator_frame_attempts which block lane coordinate))
  by_cases first : block.val = 0
  · rw [if_pos first]
    simp only [first] at targetValue
    apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
      (accumulator_frame_constant_canonical _ _)
    simpa only [accumulatorFrameAttempt, attempt, first, ↓reduceIte, List.append_nil,
      csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      one, targetValue, one_mul, add_zero, packedWord] using equation
  · rw [if_neg first]
    apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (Nat.mod_lt _ (by decide))
    change (packedWord packed (hashInitialIndex (accumulatorCall which.val + block.val) lane.val) :
        ZMod 18446744069414584321) =
      (((packedWord packed (hashFinalIndex (accumulatorCall which.val + block.val - 1) lane.val) +
        accumulatorFrameConstant block.val lane.val) % 18446744069414584321 : Nat) :
        ZMod 18446744069414584321)
    simp only [ZMod.natCast_mod, Nat.cast_add]
    simp only [accumulatorFrameAttempt, attempt, first, ↓reduceIte, List.cons_append, List.nil_append,
      csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      one, negative, targetValue, one_mul, neg_one_mul, add_zero] at equation
    change (packed.getD (hashInitialIndex (accumulatorCall which.val + block.val) lane.val) 0 :
        ZMod 18446744069414584321) +
        -(packed.getD (hashFinalIndex (accumulatorCall which.val + block.val - 1) lane.val) 0 :
          ZMod 18446744069414584321) =
      (accumulatorFrameConstant block.val lane.val : ZMod 18446744069414584321) at equation
    simp only [packedWord]
    linear_combination equation

theorem accumulator_words_getD (packed : List Nat) (which : Nat) {word : Nat} (bound : word < 23) :
    (accumulatorWords packed which).getD word 0 = spongeSourceWord packed (accumulatorCall which) word := by
  simp [accumulatorWords, List.getD_eq_getElem?_getD, bound]

theorem project_accumulator_exact_words (packed : List Nat) (which : Nat) :
    exactV8AccumulatorWords (projectAccumulator packed (accumulatorCall which)) = accumulatorWords packed which := by
  rfl

theorem accepted_accumulator_first_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    packedInitialState packed (accumulatorCall which.val) = accumulatorFirstFrame (accumulatorWords packed which.val) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  by_cases rate : lane < 8
  · change _ = (if lane < 8 then Poseidon2Width16Kernel.fieldAdd 0
      ((accumulatorWords packed which.val).getD lane 0) else _)
    rw [if_pos rate, accumulator_words_getD packed which.val (by omega)]
    have block : lane / 8 = 0 := Nat.div_eq_of_lt rate
    have index : lane % 8 = lane := Nat.mod_eq_of_lt rate
    have bound := sponge_source_word_canonical accepted.2.1 (accumulatorCall which.val) lane
    simp only [Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
    change _ = spongeSourceWord packed (accumulatorCall which.val) lane % 18446744069414584321
    have canonical : spongeSourceWord packed (accumulatorCall which.val) lane < 18446744069414584321 := bound
    rw [Nat.mod_eq_of_lt canonical]
    simp only [spongeSourceWord, block, index, ↓reduceIte, Nat.add_zero]
  · change _ = (if lane < 8 then _ else _)
    rw [if_neg rate]
    simpa only [Nat.add_zero, ↓reduceIte, accumulatorFrameConstant] using
      accepted_accumulator_frame_coordinate accepted which ⟨0, by decide⟩ ⟨lane, laneBound⟩
        (Or.inl (show 8 ≤ lane from by omega))

theorem accepted_accumulator_middle_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    packedInitialState packed (accumulatorCall which.val + 1) =
      accumulatorMiddleFrame (accumulatorWords packed which.val) (packedFinalState packed (accumulatorCall which.val)) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have previous : accumulatorCall which.val + 1 - 1 = accumulatorCall which.val := by omega
  by_cases rate : lane < 8
  · change _ = (if lane < 8 then Poseidon2Width16Kernel.fieldAdd
      ((packedFinalState packed (accumulatorCall which.val)).getD lane 0)
      ((accumulatorWords packed which.val).getD (8 + lane) 0) else _)
    rw [if_pos rate, accumulator_words_getD packed which.val (by omega), packed_final_getD packed _ laneBound]
    change _ = fieldAdd _ _
    simpa only [Nat.one_mul, Nat.one_ne_zero, ↓reduceIte, previous] using
      accepted_note_absorbed_coordinate accepted (accumulatorCall which.val) 1 lane rate
  · change _ = (if lane < 8 then _ else (packedFinalState packed (accumulatorCall which.val)).getD lane 0)
    rw [if_neg rate, packed_final_getD packed _ laneBound]
    have source := accepted_accumulator_frame_coordinate accepted which ⟨1, by decide⟩ ⟨lane, laneBound⟩
      (Or.inl (show 8 ≤ lane from by omega))
    simp only [accumulatorFrameConstant, Nat.one_ne_zero, show (1 : Nat) ≠ 2 by decide,
      ↓reduceIte, false_and, previous] at source
    rw [source]
    exact Nat.mod_eq_of_lt (packed_word_canonical accepted.2.1 _)

theorem accepted_accumulator_last_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    packedInitialState packed (accumulatorCall which.val + 2) =
      accumulatorLastFrame (accumulatorWords packed which.val) (packedFinalState packed (accumulatorCall which.val + 1)) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have previous : accumulatorCall which.val + 2 - 1 = accumulatorCall which.val + 1 := by omega
  by_cases rate : lane < 7
  · change _ = (if lane < 7 then Poseidon2Width16Kernel.fieldAdd
      ((packedFinalState packed (accumulatorCall which.val + 1)).getD lane 0)
      ((accumulatorWords packed which.val).getD (16 + lane) 0) else _)
    rw [if_pos rate, accumulator_words_getD packed which.val (by omega), packed_final_getD packed _ laneBound]
    change _ = fieldAdd _ _
    simpa only [Nat.reduceMul, show (2 : Nat) ≠ 0 by decide, ↓reduceIte, previous] using
      accepted_note_absorbed_coordinate accepted (accumulatorCall which.val) 2 lane (by omega)
  · change _ = (if lane < 7 then _ else if lane = 11 then
      Poseidon2Width16Kernel.fieldAdd ((packedFinalState packed (accumulatorCall which.val + 1)).getD lane 0) 1
      else (packedFinalState packed (accumulatorCall which.val + 1)).getD lane 0)
    rw [if_neg rate, packed_final_getD packed _ laneBound]
    have coordinate : 8 ≤ lane ∨ 2 = 2 ∧ lane = 7 := by omega
    have source := accepted_accumulator_frame_coordinate accepted which ⟨2, by decide⟩ ⟨lane, laneBound⟩ coordinate
    simp only [accumulatorFrameConstant, show (2 : Nat) ≠ 0 by decide,
      ↓reduceIte, true_and, previous] at source
    by_cases marker : lane = 11
    · simp only [if_pos marker]
      change _ = fieldAdd _ _
      simpa only [if_pos marker] using source
    · simp only [if_neg marker]
      rw [if_neg marker] at source
      rw [source]
      exact Nat.mod_eq_of_lt (packed_word_canonical accepted.2.1 _)

/-- Both current and next accepted accumulator traces implement the exact
existing23-word semantic hash of their actual projected openings. -/
theorem accepted_accumulator_digest_eq_exact {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (which : Fin 2) :
    (packedFinalState packed (accumulatorCall which.val + 2)).take digestWords =
      exactV8AccumulatorDigest (projectAccumulator packed (accumulatorCall which.val)) := by
  have length : (accumulatorWords packed which.val).length = 23 := by simp [accumulatorWords]
  have callBound : accumulatorCall which.val + 2 < 128 := by
    have := which.isLt; unfold accumulatorCall; omega
  have first := accepted_final_state_eq_kernel accepted (call := accumulatorCall which.val) (by omega)
  have middle := accepted_final_state_eq_kernel accepted (call := accumulatorCall which.val + 1) (by omega)
  have last := accepted_final_state_eq_kernel accepted (call := accumulatorCall which.val + 2) callBound
  rw [accepted_accumulator_first_frame accepted which] at first
  rw [accepted_accumulator_middle_frame accepted which] at middle
  rw [accepted_accumulator_last_frame accepted which] at last
  unfold exactV8AccumulatorDigest
  rw [project_accumulator_exact_words]
  exact (accumulator_sponge_of_frame_chain _ _ _ _ length
    (by simp [packedFinalState]) (by simp [packedFinalState]) first.symm middle.symm last.symm).symm


end HegemonCrypto.SmallWood.V8Smz9AccumulatorSource
