import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNotes
import HegemonCrypto.SmallWoodV8Smz9NoteSpongeFold

namespace HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldAdd)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9NoteSpongeFold

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000

def packedFinalState (packed : List Nat) (call : Nat) : List Nat :=
  (List.range 16).map (fun lane => packedWord packed (hashFinalIndex call lane))

theorem kernel_permutation_length (state : List Nat) :
    (Poseidon2Width16Kernel.permutation state).length = 16 := by
  unfold Poseidon2Width16Kernel.permutation Poseidon2Width16Kernel.externalRoundConstantsTerminal
  simp only [List.foldl_cons, List.foldl_nil]
  exact Poseidon2Width16Kernel.external_round_length _ _

theorem accepted_final_state_eq_kernel {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {call : Nat} (callBound : call < 128) :
    packedFinalState packed call = Poseidon2Width16Kernel.permutation (packedInitialState packed call) := by
  apply List.ext_getElem
  · simp [packedFinalState, kernel_permutation_length]
  · intro lane leftBound rightBound
    have laneBound : lane < 16 := by simpa [packedFinalState] using leftBound
    simp only [packedFinalState, List.getElem_map, List.getElem_range]
    rw [← List.getD_eq_getElem _ _ rightBound]
    exact accepted_hash_call_final_eq_kernel accepted callBound laneBound

def notePreparedLane (packed : List Nat) (note block lane : Nat) : Nat :=
  let call := noteBridgeCall note + block
  if block = 0 then
    if lane < 8 then spongeSourceWord packed (noteBridgeCall note) lane
    else noteFrameConstant block lane
  else if lane < 8 ∧ block * 8 + lane < 18 then
    fieldAdd (packedWord packed (hashFinalIndex (call - 1) lane))
      (spongeSourceWord packed (noteBridgeCall note) (block * 8 + lane))
  else fieldAdd (packedWord packed (hashFinalIndex (call - 1) lane))
    (noteFrameConstant block lane)

theorem accepted_note_initial_lane {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (note : Fin 4) (block : Fin 3) (lane : Fin 16) :
    packedWord packed (hashInitialIndex (noteBridgeCall note.val + block.val) lane.val) =
      notePreparedLane packed note.val block.val lane.val := by
  unfold notePreparedLane
  by_cases first : block.val = 0
  · rw [if_pos first]
    by_cases rate : lane.val < 8
    · rw [if_pos rate]
      simpa only [first, Nat.zero_mul, Nat.zero_add, if_true] using
        accepted_note_absorbed_coordinate accepted (noteBridgeCall note.val) block.val lane.val rate
    · rw [if_neg rate]
      simpa only [first, if_true] using
        accepted_note_frame_coordinate accepted note block lane ⟨block.isLt, lane.isLt, Or.inl (by omega)⟩
  · rw [if_neg first]
    by_cases absorbed : lane.val < 8 ∧ block.val * 8 + lane.val < 18
    · rw [if_pos absorbed]
      simpa only [if_neg first] using
        accepted_note_absorbed_coordinate accepted (noteBridgeCall note.val) block.val lane.val absorbed.1
    · rw [if_neg absorbed]
      apply (accepted_note_frame_coordinate accepted note block lane _).trans
      · rw [if_neg first]
      · exact ⟨block.isLt, lane.isLt, by omega⟩

theorem accepted_note_initial_state {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (note : Fin 4) (block : Fin 3) :
    packedInitialState packed (noteBridgeCall note.val + block.val) =
      (List.range 16).map (notePreparedLane packed note.val block.val) := by
  apply List.map_congr_left
  intro lane member
  exact accepted_note_initial_lane accepted note block ⟨lane, List.mem_range.mp member⟩

theorem project_note_exact_input_words (packed : List Nat) (call : Nat) :
    exactV8NoteWords (projectNote packed call) =
      (List.range 18).map (spongeSourceWord packed call) := by
  rfl

def noteWords (packed : List Nat) (note : Nat) : List Nat :=
  (List.range 18).map (spongeSourceWord packed (noteBridgeCall note))

theorem note_words_getD (packed : List Nat) (note : Nat) {word : Nat} (bound : word < 18) :
    (noteWords packed note).getD word 0 = spongeSourceWord packed (noteBridgeCall note) word := by
  simp [noteWords, List.getD_eq_getElem?_getD, bound]

theorem packed_final_getD (packed : List Nat) (call : Nat) {lane : Nat} (bound : lane < 16) :
    (packedFinalState packed call).getD lane 0 = packedWord packed (hashFinalIndex call lane) := by
  simp [packedFinalState, List.getD_eq_getElem?_getD, bound]

theorem accepted_note_first_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (note : Fin 4) :
    packedInitialState packed (noteBridgeCall note.val) = noteFirstFrame (noteWords packed note.val) := by
  have initial := accepted_note_initial_state accepted note ⟨0, by decide⟩
  simp only [Nat.add_zero] at initial
  rw [initial]
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have sourceBound := sponge_source_word_canonical accepted.2.1 (noteBridgeCall note.val) lane
  by_cases rate : lane < 8
  · have wordBound : lane < 18 := by omega
    change _ = (if lane < 8 then Poseidon2Width16Kernel.fieldAdd 0
      ((noteWords packed note.val).getD lane 0) else _)
    rw [if_pos rate, note_words_getD packed note.val wordBound]
    simp only [notePreparedLane, ↓reduceIte, rate]
    simp only [Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
    change spongeSourceWord packed (noteBridgeCall note.val) lane =
      spongeSourceWord packed (noteBridgeCall note.val) lane % 18446744069414584321
    exact (Nat.mod_eq_of_lt sourceBound).symm
  · simp [notePreparedLane, noteFrameConstant, rate]

theorem accepted_note_middle_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (note : Fin 4) :
    packedInitialState packed (noteBridgeCall note.val + 1) =
      noteMiddleFrame (noteWords packed note.val) (packedFinalState packed (noteBridgeCall note.val)) := by
  rw [accepted_note_initial_state accepted note ⟨1, by decide⟩]
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have sourceBound := packed_word_canonical accepted.2.1 (hashFinalIndex (noteBridgeCall note.val) lane)
  have previous : noteBridgeCall note.val + 1 - 1 = noteBridgeCall note.val := by omega
  by_cases rate : lane < 8
  · have wordBound : 8 + lane < 18 := by omega
    change _ = (if lane < 8 then Poseidon2Width16Kernel.fieldAdd
      ((packedFinalState packed (noteBridgeCall note.val)).getD lane 0)
      ((noteWords packed note.val).getD (8 + lane) 0) else _)
    rw [if_pos rate, note_words_getD packed note.val wordBound,
      packed_final_getD packed _ laneBound]
    simp only [notePreparedLane, ↓reduceIte, Nat.one_mul, rate, wordBound, and_self,
      previous]
    rfl
  · change _ = (if lane < 8 then _ else (packedFinalState packed (noteBridgeCall note.val)).getD lane 0)
    rw [if_neg rate, packed_final_getD packed _ laneBound]
    simp only [notePreparedLane, noteFrameConstant, ↓reduceIte, rate, false_and,
      previous]
    exact Nat.mod_eq_of_lt sourceBound

theorem accepted_note_last_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (note : Fin 4) :
    packedInitialState packed (noteBridgeCall note.val + 2) =
      noteLastFrame (noteWords packed note.val) (packedFinalState packed (noteBridgeCall note.val + 1)) := by
  rw [accepted_note_initial_state accepted note ⟨2, by decide⟩]
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have sourceBound := packed_word_canonical accepted.2.1 (hashFinalIndex (noteBridgeCall note.val + 1) lane)
  have previous : noteBridgeCall note.val + 2 - 1 = noteBridgeCall note.val + 1 := by omega
  by_cases active : lane < 2
  · have wordBound : 16 + lane < 18 := by omega
    have rate : lane < 8 := by omega
    change _ = (if lane < 2 then Poseidon2Width16Kernel.fieldAdd
      ((packedFinalState packed (noteBridgeCall note.val + 1)).getD lane 0)
      ((noteWords packed note.val).getD (16 + lane) 0) else _)
    rw [if_pos active, note_words_getD packed note.val wordBound,
      packed_final_getD packed _ laneBound]
    simp only [notePreparedLane, ↓reduceIte, Nat.reduceMul, rate, wordBound,
      and_self, previous]
    rfl
  · have outside : ¬16 + lane < 18 := by omega
    change _ = (if lane < 2 then _ else if lane = 11 then
      Poseidon2Width16Kernel.fieldAdd ((packedFinalState packed (noteBridgeCall note.val + 1)).getD lane 0) 1
      else (packedFinalState packed (noteBridgeCall note.val + 1)).getD lane 0)
    rw [if_neg active, packed_final_getD packed _ laneBound]
    simp only [notePreparedLane, noteFrameConstant, Nat.succ_ne_zero, ↓reduceIte, Nat.reduceMul,
      outside, and_false, true_and, previous]
    by_cases marker : lane = 11
    · simp only [if_pos marker]
      rfl
    · simp only [if_neg marker]
      exact Nat.mod_eq_of_lt sourceBound

/-- Every accepted note trace is the exact existing semantic note sponge,
with the actual projected private opening and all three chained permutations. -/
theorem accepted_note_digest_eq_exact_commitment {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (note : Fin 4) :
    (packedFinalState packed (noteBridgeCall note.val + 2)).take digestWords =
      exactV8NoteCommitment (projectNote packed (noteBridgeCall note.val)) := by
  have inputsLength : (noteWords packed note.val).length = 18 := by simp [noteWords]
  have calls : noteBridgeCall note.val + 2 < 128 := by fin_cases note <;> decide
  have final0 := accepted_final_state_eq_kernel accepted (call := noteBridgeCall note.val) (by omega)
  have final1 := accepted_final_state_eq_kernel accepted (call := noteBridgeCall note.val + 1) (by omega)
  have final2 := accepted_final_state_eq_kernel accepted (call := noteBridgeCall note.val + 2) calls
  rw [accepted_note_first_frame accepted note] at final0
  rw [accepted_note_middle_frame accepted note] at final1
  rw [accepted_note_last_frame accepted note] at final2
  unfold exactV8NoteCommitment
  rw [project_note_exact_input_words]
  change _ = poseidon2V8Sponge poseidon2V8NoteDomain (noteWords packed note.val)
  rw [note_sponge_three_blocks _ inputsLength,
    note_absorb_first _ inputsLength, ← final0,
    note_absorb_middle _ _ inputsLength (by simp [packedFinalState]), ← final1,
    note_absorb_last _ _ inputsLength (by simp [packedFinalState]), ← final2]


end HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
