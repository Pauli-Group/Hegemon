import HegemonCrypto.SmallWoodV8Smz9ValueLockSponge
import HegemonCrypto.SmallWoodV8Smz9AuthorizationDigestCopies

namespace HegemonCrypto.SmallWood.V8Smz9ValueLockSource

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (CsrExecutableAttempt evalFieldExpression fieldSub fieldNormalize fieldAdd)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9AuthorizationDigestCopies
open HegemonCrypto.SmallWood.V8Smz9ValueLockSponge
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def valueLockWordAttempt (word : Nat) : CsrExecutableAttempt :=
  let block := word / 8
  let call := 104 + block
  attempt (19081 + 16 * block + word % 8) 33 (16 * block + word % 8) 0
    ([(hashInitialIndex call (word % 8), 1)] ++
      (if block = 0 then [] else [(hashFinalIndex (call - 1) (word % 8), 158)]) ++
      [(rawIndex (138 + word), 158)]) 0

theorem value_lock_word_source (word : Nat) (bound : word < 14) :
    valueLockWordAttempt word ∈ exactCsrAttempts := by
  have checked : ∀ word : Fin 14, valueLockWordAttempt word.val ∈
      V8Smz9ProgramCanonicalityCsr37.chunkList.flatten := by decide
  obtain ⟨chunk, member, entry⟩ := List.mem_flatten.mp (checked ⟨word, bound⟩)
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, authorization_csr_chunk_mem_exact member, entry⟩

theorem accepted_value_lock_source_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {word : Nat} (bound : word < 14) :
    spongeSourceWord packed 104 word = authorizationRawWord packed (138 + word) := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp only [List.getD_eq_getElem?_getD, constants.1, Option.getD_some, Nat.cast_zero]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp only [List.getD_eq_getElem?_getD, constants.2, Option.getD_some, Nat.cast_one]
  have negativeOne : (values.getD 158 0 : F) = -1 := by
    simpa using (dense_negative_coefficient_values equations).1 0 (by decide)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (value_lock_word_source word bound))
  apply canonical_nat_cast_injective (sponge_source_word_canonical accepted.2.1 _ _)
    (packed_word_canonical accepted.2.1 _)
  by_cases firstBlock : word / 8 = 0
  · simp only [valueLockWordAttempt, attempt, firstBlock, if_true,
      List.append_nil, List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    have equality := sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using equation)
    simpa only [spongeSourceWord, firstBlock, if_true, Nat.add_zero,
      authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.zero_add, packedWord] using equality
  · simp only [valueLockWordAttempt, attempt, firstBlock, if_false,
      List.cons_append, List.nil_append, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      oneValue, negativeOne, zeroValue, one_mul, neg_one_mul, add_zero] at equation
    simp only [spongeSourceWord, firstBlock, if_false]
    rw [field_sub_cast _ _ (by
      have previous := packed_word_canonical accepted.2.1 (hashFinalIndex (104 + word / 8 - 1) (word % 8))
      change _ < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus at previous
      omega)]
    have equality : (packed.getD (hashInitialIndex (104 + word / 8) (word % 8)) 0 : F) -
        (packed.getD (hashFinalIndex (104 + word / 8 - 1) (word % 8)) 0 : F) =
        (packed.getD (rawIndex (138 + word)) 0 : F) := by
      exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg, add_assoc] using equation)
    simpa only [packedWord, authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using equality


def valueLockFrameTarget (block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then 207 else if lane = 9 then 550 else
    if lane = 10 then 543 else if lane = 15 then 544 else 0
  else if lane = 11 then 1 else 0

def valueLockFrameConstant (block lane : Nat) : Nat :=
  if block = 0 then
    if lane = 8 then 8 else if lane = 9 then 14 else
    if lane = 10 then poseidon2V8SpongeModeMarker else
    if lane = 15 then poseidon2V8SuiteMarker else 0
  else if lane = 11 then 1 else 0

def valueLockFrameAttempt (block lane : Nat) : CsrExecutableAttempt :=
  let call := 104 + block
  attempt (19081 + 16 * block + lane) 33 (16 * block + lane) 0
    ([(hashInitialIndex call lane, 1)] ++
      if block = 0 then [] else [(hashFinalIndex (call - 1) lane, 158)])
    (valueLockFrameTarget block lane)

theorem value_lock_frame_source (block : Fin 2) (lane : Fin 16)
    (coordinate : 8 ≤ lane.val ∨ block.val = 1 ∧ 6 ≤ lane.val) :
    valueLockFrameAttempt block.val lane.val ∈ exactCsrAttempts := by
  have checked : ∀ block : Fin 2, ∀ lane : Fin 16,
      (8 ≤ lane.val ∨ block.val = 1 ∧ 6 ≤ lane.val) →
        valueLockFrameAttempt block.val lane.val ∈
          V8Smz9ProgramCanonicalityCsr37.chunkList.flatten := by decide
  obtain ⟨chunk, member, entry⟩ := List.mem_flatten.mp (checked block lane coordinate)
  rw [← V8Smz9ProgramCanonicalityGenerated.csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨chunk, authorization_csr_chunk_mem_exact member, entry⟩

theorem value_lock_frame_target (block : Fin 2) (lane : Fin 16) :
    exactCsrExpressions[valueLockFrameTarget block.val lane.val]? =
      some (.constant (valueLockFrameConstant block.val lane.val)) := by
  have checked : ∀ block : Fin 2, ∀ lane : Fin 16,
      exactCsrExpressions[valueLockFrameTarget block.val lane.val]? =
        some (.constant (valueLockFrameConstant block.val lane.val)) := by decide
  exact checked block lane

theorem value_lock_frame_constant_canonical (block lane : Nat) :
    valueLockFrameConstant block lane < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
  unfold valueLockFrameConstant
  split_ifs <;> decide

theorem accepted_value_lock_frame_coordinate {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (block : Fin 2) (lane : Fin 16)
    (coordinate : 8 ≤ lane.val ∨ block.val = 1 ∧ 6 ≤ lane.val) :
    packedWord packed (hashInitialIndex (104 + block.val) lane.val) =
      if block.val = 0 then valueLockFrameConstant block.val lane.val else
        fieldAdd (packedWord packed (hashFinalIndex (104 + block.val - 1) lane.val))
          (valueLockFrameConstant block.val lane.val) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negValue : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zeroValue, oneValue, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have targetValue : (values.getD (valueLockFrameTarget block.val lane.val) 0 : F) =
      (valueLockFrameConstant block.val lane.val : F) := by
    simpa only [expressionField] using equations _ _ (value_lock_frame_target block lane)
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (value_lock_frame_source block lane coordinate))
  have initialBound := packed_word_canonical accepted.2.1 (hashInitialIndex (104 + block.val) lane.val)
  by_cases first : block.val = 0
  · rw [if_pos first]
    apply canonical_nat_cast_injective initialBound (value_lock_frame_constant_canonical _ _)
    simp only [valueLockFrameAttempt, attempt, if_pos first, List.append_nil, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at equation
    rw [oneValue, one_mul, add_zero, targetValue] at equation
    exact equation
  · rw [if_neg first]
    apply canonical_nat_cast_injective initialBound (Nat.mod_lt _ (by decide))
    change (packedWord packed (hashInitialIndex (104 + block.val) lane.val) : F) =
      (fieldAdd (packedWord packed (hashFinalIndex (104 + block.val - 1) lane.val))
        (valueLockFrameConstant block.val lane.val) : F)
    rw [field_add_cast]
    have difference :
        (packedWord packed (hashInitialIndex (104 + block.val) lane.val) : F) -
          (packedWord packed (hashFinalIndex (104 + block.val - 1) lane.val) : F) =
            (valueLockFrameConstant block.val lane.val : F) := by
      simp only [valueLockFrameAttempt, attempt, if_neg first, List.cons_append,
        List.nil_append, csrFieldSum, List.map_cons, List.map_nil,
        List.sum_cons, List.sum_nil] at equation
      rw [oneValue, one_mul, negValue, neg_one_mul, add_zero, targetValue] at equation
      simpa only [packedWord, sub_eq_add_neg] using equation
    exact (sub_eq_iff_eq_add.mp difference).trans (add_comm _ _)

def valueLockWords (packed : List Nat) : List Nat :=
  (List.range 14).map (spongeSourceWord packed 104)

theorem value_lock_words_getD (packed : List Nat) {word : Nat} (bound : word < 14) :
    (valueLockWords packed).getD word 0 = spongeSourceWord packed 104 word := by
  simp [valueLockWords, List.getD_eq_getElem?_getD, bound]

theorem accepted_value_lock_first_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedInitialState packed 104 = valueLockFirstFrame (valueLockWords packed) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  by_cases rate : lane < 8
  · change _ = (if lane < 8 then Poseidon2Width16Kernel.fieldAdd 0
      ((valueLockWords packed).getD lane 0) else _)
    rw [if_pos rate, value_lock_words_getD packed (by omega)]
    have source := accepted_note_absorbed_coordinate accepted 104 0 lane rate
    simp only [Nat.add_zero, Nat.zero_mul, Nat.zero_add, if_true] at source
    rw [source]
    simp only [Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
    exact (Nat.mod_eq_of_lt (sponge_source_word_canonical accepted.2.1 104 lane)).symm
  · have coordinate := accepted_value_lock_frame_coordinate accepted ⟨0, by decide⟩ ⟨lane, laneBound⟩
      (Or.inl (by change 8 ≤ lane; omega))
    simpa only [valueLockFirstFrame, valueLockFrameConstant, Nat.add_zero, if_true,
      if_neg rate] using coordinate

theorem accepted_value_lock_last_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedInitialState packed 105 = valueLockLastFrame (valueLockWords packed) (packedFinalState packed 104) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  by_cases rate : lane < 6
  · change _ = (if lane < 6 then Poseidon2Width16Kernel.fieldAdd
      ((packedFinalState packed 104).getD lane 0) ((valueLockWords packed).getD (8 + lane) 0) else _)
    rw [if_pos rate, value_lock_words_getD packed (by omega), packed_final_getD packed 104 laneBound]
    change _ = fieldAdd _ _
    have source := accepted_note_absorbed_coordinate accepted 104 1 lane (by omega)
    simpa only [Nat.one_ne_zero, if_false, Nat.one_mul, Nat.reduceAdd, Nat.reduceSub] using source
  · change _ = (if lane < 6 then _ else if lane = 11 then
      Poseidon2Width16Kernel.fieldAdd ((packedFinalState packed 104).getD lane 0) 1
      else (packedFinalState packed 104).getD lane 0)
    rw [if_neg rate, packed_final_getD packed 104 laneBound]
    have coordinate := accepted_value_lock_frame_coordinate accepted ⟨1, by decide⟩ ⟨lane, laneBound⟩
      (Or.inr ⟨rfl, by change 6 ≤ lane; omega⟩)
    simp only [valueLockFrameConstant, Nat.one_ne_zero, if_false, Nat.reduceAdd, Nat.reduceSub] at coordinate
    by_cases marker : lane = 11
    · rw [if_pos marker]
      change _ = fieldAdd _ _
      simpa only [if_pos marker] using coordinate
    · rw [if_neg marker]
      simp only [if_neg marker, fieldAdd, Nat.add_zero] at coordinate
      exact coordinate.trans (Nat.mod_eq_of_lt (packed_word_canonical accepted.2.1 _))

theorem accepted_value_lock_words_current {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    valueLockWords packed = (projectAccumulator packed 98).policyRoot ++
      (projectAccumulator packed 98).intentDigest := by
  have source : valueLockWords packed = (List.range 14).map (spongeSourceWord packed 98) := by
    apply List.map_congr_left
    intro word member
    have bound := List.mem_range.mp member
    rw [accepted_value_lock_source_word accepted bound,
      accepted_current_opening_source_word accepted (by omega)]
  change _ = (List.range 7).map (spongeSourceWord packed 98) ++
    (List.range 7).map (fun limb => spongeSourceWord packed 98 (7 + limb))
  rw [source]
  simpa only [List.map_append, List.map_map, Function.comp_def] using
    congrArg (List.map (spongeSourceWord packed 98)) (@List.range_add 7 7)

theorem accepted_value_lock_digest_eq_exact {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (packedFinalState packed 105).take digestWords =
      exactV8ValueLockDigest (projectAccumulator packed 98) := by
  have composition := value_lock_sponge_of_frame_chain (valueLockWords packed)
    (packedFinalState packed 104) (packedFinalState packed 105)
    (by simp [valueLockWords]) (by simp [packedFinalState])
    ((congrArg Poseidon2Width16Kernel.permutation (accepted_value_lock_first_frame accepted)).symm.trans
      (accepted_final_state_eq_kernel accepted (by decide)).symm)
    ((congrArg Poseidon2Width16Kernel.permutation (accepted_value_lock_last_frame accepted)).symm.trans
      (accepted_final_state_eq_kernel accepted (by decide)).symm)
  rw [accepted_value_lock_words_current accepted] at composition
  exact composition.symm


end HegemonCrypto.SmallWood.V8Smz9ValueLockSource
