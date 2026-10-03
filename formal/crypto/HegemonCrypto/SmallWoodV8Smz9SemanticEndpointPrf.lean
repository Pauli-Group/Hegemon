import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNoteComposition

namespace HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (CsrExecutableAttempt)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def prfFrameTarget (lane : Nat) : Nat :=
  if lane = 8 then 2 else if lane = 9 then 128 else if lane = 10 then 543 else
  if lane = 11 then 1 else if lane = 15 then 544 else 0

def prfFrameConstant (lane : Nat) : Nat :=
  if lane = 8 then 2 else if lane = 9 then 4 else if lane = 10 then poseidon2V8SpongeModeMarker else
  if lane = 11 then 1 else if lane = 15 then poseidon2V8SuiteMarker else 0

def prfFrameAttempt (lane : Nat) : CsrExecutableAttempt :=
  attempt (15789 + lane) 10 lane 0 [(hashInitialIndex 0 lane, 1)] (prfFrameTarget lane)

theorem prf_frame_source (lane : Fin 16) (padding : 4 ≤ lane.val) :
    prfFrameAttempt lane.val ∈ exactCsrAttempts := by
  have member : V8Smz9ProgramCanonicalityCsr30.chunk013 ∈
      V8Smz9ProgramCanonicalityCsr30.chunkList := by
    simp [V8Smz9ProgramCanonicalityCsr30.chunkList]
  have checked : ∀ lane : Fin 16, 4 ≤ lane.val →
      prfFrameAttempt lane.val ∈ V8Smz9ProgramCanonicalityCsr30.chunk013 := by decide
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  apply List.mem_flatten_of_mem _ (checked lane padding)
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
  simp only [List.mem_append]
  aesop

theorem prf_frame_constant_node : ∀ lane : Fin 16,
    exactCsrExpressions[prfFrameTarget lane.val]? = some (.constant (prfFrameConstant lane.val)) := by
  decide

theorem prf_frame_constant_bound (lane : Nat) : prfFrameConstant lane < fieldModulus := by
  unfold prfFrameConstant
  split_ifs <;> decide

/-- All twelve call-0 capacity/padding words follow from actual source CSR equations. -/
theorem accepted_prf_frame_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (lane : Fin 16) (padding : 4 ≤ lane.val) :
    packedWord packed (hashInitialIndex 0 lane.val) = prfFrameConstant lane.val := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have targetValue : (values.getD (prfFrameTarget lane.val) 0 : F) =
      (prfFrameConstant lane.val : F) := by
    simpa only [expressionField] using equations _ _ (prf_frame_constant_node lane)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (prf_frame_source lane padding))
  simp only [prfFrameAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil] at equation
  rw [oneValue, one_mul, add_zero, targetValue] at equation
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (prf_frame_constant_bound lane.val) equation

def prfWords (packed : List Nat) : List Nat :=
  (List.range 4).map (spongeSourceWord packed 0)

def prfFirstFrame (inputs : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 4 then Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0)
    else prfFrameConstant lane

theorem exact_prf_sponge_one_block (inputs : List Nat) (length : inputs.length = 4) :
    exactV8TransactionPrf inputs = (Poseidon2Width16Kernel.permutation (prfFirstFrame inputs)).take digestWords := by
  have one : Poseidon2Width16Kernel.fieldAdd 0 1 = 1 := by decide
  simp [exactV8TransactionPrf, poseidon2V8Sponge, poseidon2V8AbsorbBlock,
    poseidon2V8InitialState, poseidon2V8SeedFirstBlock, poseidon2V8NullifierDomain,
    Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate, length, prfFirstFrame,
    prfFrameConstant, List.range_succ, List.replicate_succ, List.getD, one]

theorem accepted_prf_initial_state {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedInitialState packed 0 = prfFirstFrame (prfWords packed) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  by_cases privateWord : lane < 4
  · change packedWord packed (hashInitialIndex 0 lane) =
      (if lane < 4 then Poseidon2Width16Kernel.fieldAdd 0 ((prfWords packed).getD lane 0) else _)
    rw [if_pos privateWord]
    have source : (prfWords packed).getD lane 0 = spongeSourceWord packed 0 lane := by
      simp [prfWords, List.getD_eq_getElem?_getD, privateWord]
    rw [source]
    have initial := accepted_note_absorbed_coordinate accepted 0 0 lane (by omega)
    simp only [Nat.zero_add, Nat.zero_mul, ↓reduceIte] at initial
    rw [initial]
    simp only [Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
    change spongeSourceWord packed 0 lane = spongeSourceWord packed 0 lane % 18446744069414584321
    exact (Nat.mod_eq_of_lt (sponge_source_word_canonical accepted.2.1 0 lane)).symm
  · change _ = (if lane < 4 then _ else prfFrameConstant lane)
    rw [if_neg privateWord]
    exact accepted_prf_frame_word accepted ⟨lane, laneBound⟩ (by change 4 ≤ lane; omega)

/-- Exact call-0 transaction PRF, derived for every accepted packed assignment. -/
theorem accepted_prf_digest_eq_exact {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (packedFinalState packed 0).take digestWords = exactV8TransactionPrf (prfWords packed) := by
  rw [exact_prf_sponge_one_block _ (by simp [prfWords]),
    accepted_final_state_eq_kernel accepted (by decide), accepted_prf_initial_state accepted]


end HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf
