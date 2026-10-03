import HegemonCrypto.SmallWoodV8Smz9SemanticPoseidonKernelBinding
import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness

/-! Source sponge framing for all four actual V8 note calls. The arbitrary
accepted assignment is the only private input: no honest lowering or semantic
hash equation is a premise. -/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (CsrExecutableAttempt FieldExpression evalFieldExpression fieldNormalize fieldSub fieldAdd)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000

def noteFrameTarget (block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then 1 else if lane = 9 then 414 else
    if lane = 10 then 543 else if lane = 15 then 544 else 0
  else if block = 2 ∧ lane = 11 then 1 else 0

def noteFrameConstant (block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then 1 else if lane = 9 then 18 else
    if lane = 10 then poseidon2V8SpongeModeMarker else
    if lane = 15 then poseidon2V8SuiteMarker else 0
  else if block = 2 ∧ lane = 11 then 1 else 0

def noteFrameLocal (block lane : Nat) : Nat :=
  if block = 0 then lane - 6 else if block = 1 then lane + 4 else lane + 20

def noteFrameAttempt (note block lane : Nat) : CsrExecutableAttempt :=
  let offset := noteFrameLocal block lane
  let call := noteBridgeCall note + block
  attempt (noteBridgeAttemptIndex note + offset) (if note < 2 then 12 else 21)
    (36 * (note % 2) + offset) 0
    ([(hashInitialIndex call lane, 1)] ++
      if block = 0 then [] else [(hashFinalIndex (call - 1) lane, 158)])
    (noteFrameTarget block lane)

def NoteFrameCoordinate (block lane : Nat) : Prop :=
  block < 3 ∧ lane < 16 ∧ (8 ≤ lane ∨ block = 2 ∧ 2 ≤ lane)

instance (block lane : Nat) : Decidable (NoteFrameCoordinate block lane) := by
  unfold NoteFrameCoordinate
  infer_instance

def noteFrameFilter (entry : CsrExecutableAttempt) : Bool :=
  (entry.family == 12 || entry.family == 21) &&
    !([0, 1, 10, 11, 20, 21].contains (entry.localIndex % 36))

def noteFrameSources : List CsrExecutableAttempt :=
  (List.range 4).flatMap fun note => (List.range 3).flatMap fun block =>
    (List.range (if block = 2 then 14 else 8)).map fun lane =>
      noteFrameAttempt note block ((if block = 2 then 2 else 8) + lane)

def noteFrameChunks : List (List CsrExecutableAttempt) :=
  [V8Smz9ProgramCanonicalityCsr30.chunk014, V8Smz9ProgramCanonicalityCsr30.chunk015,
    V8Smz9ProgramCanonicalityCsr31.chunk000, V8Smz9ProgramCanonicalityCsr35.chunk013,
    V8Smz9ProgramCanonicalityCsr35.chunk014, V8Smz9ProgramCanonicalityCsr35.chunk015]

theorem note_frame_chunk_mem_exact {chunk : List CsrExecutableAttempt}
    (member : chunk ∈ noteFrameChunks) :
    chunk ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
  simp only [noteFrameChunks, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    unfold
      V8Smz9ProgramCanonicalityGenerated.csrChunks000
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
    aesop (add simp [V8Smz9ProgramCanonicalityCsr30.chunkList,
      V8Smz9ProgramCanonicalityCsr31.chunkList, V8Smz9ProgramCanonicalityCsr35.chunkList])

theorem exact_note_frame_filter :
    noteFrameChunks.flatten.filter noteFrameFilter = noteFrameSources := by decide

theorem note_frame_source_in_chunks (note : Fin 4) (block : Fin 3) (lane : Fin 16)
    (coordinate : NoteFrameCoordinate block.val lane.val) :
    noteFrameAttempt note.val block.val lane.val ∈ noteFrameChunks.flatten := by
  apply (List.mem_filter.mp (show noteFrameAttempt note.val block.val lane.val ∈
    noteFrameChunks.flatten.filter noteFrameFilter from ?_)).1
  rw [exact_note_frame_filter]
  apply List.mem_flatMap.mpr
  refine ⟨note.val, List.mem_range.mpr note.isLt, ?_⟩
  apply List.mem_flatMap.mpr
  refine ⟨block.val, List.mem_range.mpr block.isLt, ?_⟩
  apply List.mem_map.mpr
  by_cases last : block.val = 2
  · refine ⟨lane.val - 2, List.mem_range.mpr ?_, ?_⟩
    · simp only [if_pos last]
      unfold NoteFrameCoordinate at coordinate
      omega
    · simp only [if_pos last]
      congr 1
      unfold NoteFrameCoordinate at coordinate
      omega
  · refine ⟨lane.val - 8, List.mem_range.mpr ?_, ?_⟩
    · simp only [if_neg last]
      unfold NoteFrameCoordinate at coordinate
      omega
    · simp only [if_neg last]
      congr 1
      unfold NoteFrameCoordinate at coordinate
      omega

theorem exact_note_frame_sources (note : Fin 4) (block : Fin 3) (lane : Fin 16)
    (coordinate : NoteFrameCoordinate block.val lane.val) :
    noteFrameAttempt note.val block.val lane.val ∈ exactCsrAttempts := by
  obtain ⟨chunk, chunkMember, entryMember⟩ :=
    List.mem_flatten.mp (note_frame_source_in_chunks note block lane coordinate)
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, note_frame_chunk_mem_exact chunkMember, entryMember⟩

theorem note_frame_target_source {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (block lane : Nat) :
    values[noteFrameTarget block lane]? = some (noteFrameConstant block lane) := by
  have constants := csr_trace_zero_one_values equations
  have len : values[414]? = some 18 := by
    simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 414 (.constant 18) (by decide)
  have mode : values[543]? = some poseidon2V8SpongeModeMarker := by
    simpa [evalFieldExpression, fieldNormalize, poseidon2V8SpongeModeMarker,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 543 (.constant poseidon2V8SpongeModeMarker) (by decide)
  have suite : values[544]? = some poseidon2V8SuiteMarker := by
    simpa [evalFieldExpression, fieldNormalize, poseidon2V8SuiteMarker,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 544 (.constant poseidon2V8SuiteMarker) (by decide)
  unfold noteFrameTarget noteFrameConstant
  split_ifs <;> first | assumption | exact constants.1 | exact constants.2

theorem note_frame_constant_canonical (block lane : Nat) :
    noteFrameConstant block lane <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  unfold noteFrameConstant
  split_ifs <;> decide

/-- Every capacity lane and every repaired final-block padding lane is fixed
by the exact CSR equation, including all four actual note sponges. -/
theorem accepted_note_frame_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (note : Fin 4) (block : Fin 3) (lane : Fin 16)
    (coordinate : NoteFrameCoordinate block.val lane.val) :
    packedWord packed (hashInitialIndex (noteBridgeCall note.val + block.val) lane.val) =
      if block.val = 0 then noteFrameConstant block.val lane.val else
        fieldAdd
          (packedWord packed (hashFinalIndex (noteBridgeCall note.val + block.val - 1) lane.val))
          (noteFrameConstant block.val lane.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have negSource : values[158]? = some (fieldSub 0 1) := by
    simpa [evalFieldExpression, constants.1, constants.2] using
      equations 158 (.sub 0 1) (by decide)
  have negValue : (values.getD 158 0 : F) = -1 := by
    simp only [List.getD_eq_getElem?_getD, negSource, Option.getD_some]
    rw [field_sub_cast 0 1 (by decide)]
    simp
  have target := note_frame_target_source equations block.val lane.val
  have targetValue : (values.getD (noteFrameTarget block.val lane.val) 0 : F) =
      (noteFrameConstant block.val lane.val : F) := by
    simp [List.getD_eq_getElem?_getD, target]
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_note_frame_sources note block lane coordinate))
  have initialBound := packed_word_canonical accepted.2.1
    (hashInitialIndex (noteBridgeCall note.val + block.val) lane.val)
  by_cases first : block.val = 0
  · rw [if_pos first]
    apply canonical_nat_cast_injective initialBound (note_frame_constant_canonical _ _)
    simp only [noteFrameAttempt, attempt, if_pos first, List.append_nil, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at equation
    rw [oneValue, one_mul, add_zero, targetValue] at equation
    exact equation
  · rw [if_neg first]
    apply canonical_nat_cast_injective initialBound (Nat.mod_lt _ (by decide))
    change (packedWord packed (hashInitialIndex (noteBridgeCall note.val + block.val) lane.val) : F) =
      (fieldAdd (packedWord packed (hashFinalIndex (noteBridgeCall note.val + block.val - 1) lane.val))
        (noteFrameConstant block.val lane.val) : F)
    rw [field_add_cast]
    have difference :
        (packedWord packed (hashInitialIndex (noteBridgeCall note.val + block.val) lane.val) : F) -
          (packedWord packed (hashFinalIndex (noteBridgeCall note.val + block.val - 1) lane.val) : F) =
            (noteFrameConstant block.val lane.val : F) := by
      simp only [noteFrameAttempt, attempt, if_neg first, List.cons_append,
        List.nil_append, csrFieldSum, List.map_cons, List.map_nil,
        List.sum_cons, List.sum_nil] at equation
      rw [oneValue, one_mul, negValue, neg_one_mul, add_zero, targetValue] at equation
      simpa only [packedWord, sub_eq_add_neg] using equation
    exact (sub_eq_iff_eq_add.mp difference).trans (add_comm _ _)

theorem field_add_sub_cancel_canonical {initial previous : Nat}
    (initialBound : initial < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)
    (previousBound : previous < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus) :
    fieldAdd previous (fieldSub initial previous) = initial := by
  apply canonical_nat_cast_injective (Nat.mod_lt _ (by decide)) initialBound
  change (fieldAdd previous (fieldSub initial previous) : F) = (initial : F)
  rw [field_add_cast, field_sub_cast initial previous (by omega)]
  ring

/-- Actual in-range private source words reconstruct their absorbed state;
this identity handles arbitrary accepted coordinates, not only materialization. -/
theorem accepted_note_absorbed_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (call block lane : Nat) (laneBound : lane < 8) :
    packedWord packed (hashInitialIndex (call + block) lane) =
      if block = 0 then spongeSourceWord packed call (block * 8 + lane) else
        fieldAdd (packedWord packed (hashFinalIndex (call + block - 1) lane))
          (spongeSourceWord packed call (block * 8 + lane)) := by
  have quotient : (block * 8 + lane) / 8 = block := by omega
  have remainder : (block * 8 + lane) % 8 = lane := by omega
  simp only [spongeSourceWord, quotient, remainder]
  split_ifs
  · rfl
  · exact (field_add_sub_cancel_canonical
      (packed_word_canonical accepted.2.1 _) (packed_word_canonical accepted.2.1 _)).symm

end HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
