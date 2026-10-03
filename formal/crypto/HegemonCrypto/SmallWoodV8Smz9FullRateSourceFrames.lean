import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition

namespace HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt fieldAdd)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

/-- Kind0 is the120-word action intent; kind1 is the32-word policy opening. -/
def fullRateSourceCall (kind : Nat) : Nat := if kind = 0 then 79 else 94
def fullRateSourceBlocks (kind : Nat) : Nat := if kind = 0 then 15 else 4
def fullRateSourceDomain (kind : Nat) : Nat :=
  if kind = 0 then poseidon2V8ActionIntentDomain else poseidon2V8PolicyDomain
def fullRateSourceAttempt (kind : Nat) : Nat := if kind = 0 then 18468 else 18715

def fullRateFrameTarget (kind block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then (if kind = 0 then 546 else 548)
    else if lane = 9 then (if kind = 0 then 547 else 211)
    else if lane = 10 then 543 else if lane = 15 then 544 else 0
  else if block + 1 = fullRateSourceBlocks kind ∧ lane = 11 then 1 else 0

def fullRateFrameConstant (kind block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then fullRateSourceDomain kind
    else if lane = 9 then 8 * fullRateSourceBlocks kind
    else if lane = 10 then poseidon2V8SpongeModeMarker
    else if lane = 15 then poseidon2V8SuiteMarker else 0
  else if block + 1 = fullRateSourceBlocks kind ∧ lane = 11 then 1 else 0

def fullRateFrameAttempt (kind block lane : Nat) : CsrExecutableAttempt :=
  let call := fullRateSourceCall kind + block
  attempt (fullRateSourceAttempt kind + 16 * block + lane) (24 + 2 * kind)
    (16 * block + lane) 0
    ([(hashInitialIndex call lane, 1)] ++
      if block = 0 then [] else [(hashFinalIndex (call - 1) lane, 158)])
    (fullRateFrameTarget kind block lane)

theorem full_rate_csr_chunk_mem_exact {chunk : List CsrExecutableAttempt}
    (member : chunk ∈ V8Smz9ProgramCanonicalityCsr36.chunkList) :
    chunk ∈ V8Smz9ProgramCanonicalityGenerated.csrChunks000 := by
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
    V8Smz9ProgramCanonicalityGenerated.csrChunks036
  simp only [List.mem_append]
  aesop

theorem full_rate_frame_source (kind : Fin 2) (block : Fin 15) (lane : Fin 8)
    (within : block.val < fullRateSourceBlocks kind.val) :
    fullRateFrameAttempt kind.val block.val (8 + lane.val) ∈ exactCsrAttempts := by
  have checked : ∀ kind : Fin 2, ∀ block : Fin 15, ∀ lane : Fin 8,
      block.val < fullRateSourceBlocks kind.val →
        fullRateFrameAttempt kind.val block.val (8 + lane.val) ∈
          V8Smz9ProgramCanonicalityCsr36.chunkList.flatten := by decide
  obtain ⟨chunk, member, entry⟩ := List.mem_flatten.mp (checked kind block lane within)
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, full_rate_csr_chunk_mem_exact member, entry⟩

theorem full_rate_frame_target (kind : Fin 2) (block : Fin 15) (lane : Fin 8) :
    exactCsrExpressions[fullRateFrameTarget kind.val block.val (8 + lane.val)]? =
      some (.constant (fullRateFrameConstant kind.val block.val (8 + lane.val))) := by
  have checked : ∀ kind : Fin 2, ∀ block : Fin 15, ∀ lane : Fin 8,
      exactCsrExpressions[fullRateFrameTarget kind.val block.val (8 + lane.val)]? =
        some (.constant (fullRateFrameConstant kind.val block.val (8 + lane.val))) := by decide
  exact checked kind block lane

theorem full_rate_frame_constant_canonical (kind block lane : Nat) :
    fullRateFrameConstant kind block lane <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  unfold fullRateFrameConstant fullRateSourceDomain fullRateSourceBlocks
  split_ifs <;> decide

/-- Every full-rate action/policy capacity word is fixed by its actual source equation. -/
theorem accepted_full_rate_frame_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (kind : Fin 2) (block : Fin 15) (lane : Fin 8)
    (within : block.val < fullRateSourceBlocks kind.val) :
    packedWord packed (hashInitialIndex (fullRateSourceCall kind.val + block.val) (8 + lane.val)) =
      if block.val = 0 then fullRateFrameConstant kind.val block.val (8 + lane.val) else
        fieldAdd (packedWord packed
          (hashFinalIndex (fullRateSourceCall kind.val + block.val - 1) (8 + lane.val)))
          (fullRateFrameConstant kind.val block.val (8 + lane.val)) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negValue : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zeroValue, oneValue, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have targetValue : (values.getD (fullRateFrameTarget kind.val block.val (8 + lane.val)) 0 : F) =
      (fullRateFrameConstant kind.val block.val (8 + lane.val) : F) := by
    simpa only [expressionField] using equations _ _ (full_rate_frame_target kind block lane)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (full_rate_frame_source kind block lane within))
  have initialBound := packed_word_canonical accepted.2.1
    (hashInitialIndex (fullRateSourceCall kind.val + block.val) (8 + lane.val))
  by_cases first : block.val = 0
  · rw [if_pos first]
    apply canonical_nat_cast_injective initialBound (full_rate_frame_constant_canonical _ _ _)
    simp only [fullRateFrameAttempt, attempt, if_pos first, List.append_nil, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at equation
    rw [oneValue, one_mul, add_zero, targetValue] at equation
    exact equation
  · rw [if_neg first]
    apply canonical_nat_cast_injective initialBound (Nat.mod_lt _ (by decide))
    change (packedWord packed (hashInitialIndex (fullRateSourceCall kind.val + block.val) (8 + lane.val)) : F) =
      (fieldAdd (packedWord packed (hashFinalIndex (fullRateSourceCall kind.val + block.val - 1) (8 + lane.val)))
        (fullRateFrameConstant kind.val block.val (8 + lane.val)) : F)
    rw [field_add_cast]
    have difference :
        (packedWord packed (hashInitialIndex (fullRateSourceCall kind.val + block.val) (8 + lane.val)) : F) -
          (packedWord packed (hashFinalIndex (fullRateSourceCall kind.val + block.val - 1) (8 + lane.val)) : F) =
            (fullRateFrameConstant kind.val block.val (8 + lane.val) : F) := by
      simp only [fullRateFrameAttempt, attempt, if_neg first, List.cons_append,
        List.nil_append, csrFieldSum, List.map_cons, List.map_nil,
        List.sum_cons, List.sum_nil] at equation
      rw [oneValue, one_mul, negValue, neg_one_mul, add_zero, targetValue] at equation
      simpa only [packedWord, sub_eq_add_neg] using equation
    exact (sub_eq_iff_eq_add.mp difference).trans (add_comm _ _)


end HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames
