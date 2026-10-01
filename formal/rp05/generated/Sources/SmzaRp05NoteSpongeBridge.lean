import SmzaRp05NoteFrameSource
import SmzaRp05MerkleCallStep
import HegemonCrypto.SmallWoodV8Smz9NoteSpongeFold
import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointNotes

/-!
# Current RP05 accepted note call to exact 18-word opening

No private absorbed word is set to zero. All eighteen are the exact projected
`spongeSourceWord` values; eleven are reconstructed from initial and prior
final state. The 78 fixture CSR cells constrain the five copied sources per
input and every capacity/padding cell. Current-call final-state equality is
an explicit generic provider interface, to be instantiated by the RP05
nonlinear recurrence certificate.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05NoteSpongeBridge

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9NoteSpongeFold
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameCertificate
open HegemonCrypto.SmallWood.SmzaRp05NoteFrameSource

set_option autoImplicit false

def noteWords (packed : List Nat) (input : Fin 2) : List Nat :=
  (List.range 18).map (spongeSourceWord packed (noteCall input))

theorem note_words_shape (packed : List Nat) (input : Fin 2) :
    (noteWords packed input).length = 18 := by simp [noteWords]

theorem note_words_exact_opening (packed : List Nat) (input : Fin 2) :
    exactV8NoteWords (projectNote packed (noteCall input)) =
      noteWords packed input := by
  rfl

private theorem note_words_getD (packed : List Nat) (input : Fin 2)
    {word : Nat} (bound : word < 18) :
    (noteWords packed input).getD word 0 =
      spongeSourceWord packed (noteCall input) word := by
  simp [noteWords, List.getD_eq_getElem?_getD, bound]

private theorem final_getD (packed : List Nat) (call : Nat)
    {lane : Nat} (bound : lane < 16) :
    (packedFinalState packed call).getD lane 0 =
      packed.getD (hashFinalIndex call lane) 0 := by
  simp [packedFinalState, List.getD_eq_getElem?_getD, bound,
    HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord]

private theorem packed_option_word_canonical
    {components : RelationProgramComponents}
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) (index : Nat) :
    (packed[index]?.getD 0 : Nat) <
      Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus := by
  simpa only [List.getD_eq_getElem?_getD,
    HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord] using
      packed_word_canonical accepted.2.1 index

/-- Pure reconstruction of a private or copied absorbed word. Acceptance is
used only for canonical field representatives, not to assert a source copy. -/
theorem absorbed_coordinate
    {components : RelationProgramComponents}
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (block : Fin 3) (lane : Fin 8) :
    packed.getD (hashInitialIndex (noteCall input + block.val) lane.val) 0 =
      if block.val = 0 then
        spongeSourceWord packed (noteCall input) (block.val * 8 + lane.val)
      else fieldAdd
        (packed.getD
          (hashFinalIndex (noteCall input + block.val - 1) lane.val) 0)
        (spongeSourceWord packed (noteCall input)
          (block.val * 8 + lane.val)) := by
  have quotient : (block.val * 8 + lane.val) / 8 = block.val := by omega
  have remainder : (block.val * 8 + lane.val) % 8 = lane.val := by omega
  simp only [spongeSourceWord, quotient, remainder]
  by_cases first : block.val = 0
  · simp [first, HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord,
      List.getD_eq_getElem?_getD]
  · simp only [if_neg first]
    exact (field_add_sub_cancel_canonical
      (packed_word_canonical accepted.2.1 _)
      (packed_word_canonical accepted.2.1 _)).symm

def preparedLane (packed : List Nat) (input : Fin 2)
    (block lane : Nat) : Nat :=
  let call := noteCall input + block
  if block = 0 then
    if lane < 8 then spongeSourceWord packed (noteCall input) lane
    else noteConstant block lane
  else if lane < 8 ∧ block * 8 + lane < 18 then
    fieldAdd (packed.getD (hashFinalIndex (call - 1) lane) 0)
      (spongeSourceWord packed (noteCall input) (block * 8 + lane))
  else fieldAdd (packed.getD (hashFinalIndex (call - 1) lane) 0)
    (noteConstant block lane)

/-- Every current note-call initial lane equals the source-shaped prepared
lane. Rate lanes in range are algebraic reconstructions; other lanes are
exact emitted family14 CSR cells. -/
theorem accepted_prepared_lane
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (block : Fin 3) (lane : Fin 16) :
    packed.getD (hashInitialIndex
        (noteCall input + block.val) lane.val) 0 =
      preparedLane packed input block.val lane.val := by
  unfold preparedLane
  by_cases first : block.val = 0
  · rw [if_pos first]
    by_cases rate : lane.val < 8
    · rw [if_pos rate]
      simpa [first] using absorbed_coordinate accepted input block
        ⟨lane.val, rate⟩
    · rw [if_neg rate]
      let cell : NoteCell := (input, block, lane)
      have bound : boundCell cell := by simp [boundCell, cell, first]; omega
      have noSource : sourceIndex cell = none := by
        have notZero : lane.val ≠ 0 := by omega
        have notOne : lane.val ≠ 1 := by omega
        simp [sourceIndex, cell, first, notZero, notOne]
      simpa [cell, first, expectedConstant] using
        accepted_no_source_cell certificate accepted cell bound noSource
  · rw [if_neg first]
    by_cases inRange : lane.val < 8 ∧ block.val * 8 + lane.val < 18
    · rw [if_pos inRange]
      simpa [first] using absorbed_coordinate accepted input block
        ⟨lane.val, inRange.1⟩
    · rw [if_neg inRange]
      let cell : NoteCell := (input, block, lane)
      have blockCases : block.val = 1 ∨ block.val = 2 := by
        have blockBound := block.isLt
        omega
      have bound : boundCell cell := by
        rcases blockCases with middle | last
        · have capacity : 8 ≤ lane.val := by omega
          simp [boundCell, cell, middle, capacity]
        · simp [boundCell, cell, last]
      have noSource : sourceIndex cell = none := by
        rcases blockCases with middle | last
        · have not234 : ¬ (lane.val = 2 ∨ lane.val = 3 ∨ lane.val = 4) := by omega
          have not67 : ¬ (lane.val = 6 ∨ lane.val = 7) := by omega
          simp [sourceIndex, cell, middle, not234, not67]
        · have outside : ¬ lane.val < 2 := by omega
          simp [sourceIndex, cell, last, outside]
      simpa [cell, first, expectedConstant] using
        accepted_no_source_cell certificate accepted cell bound noSource

theorem accepted_initial_state
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (block : Fin 3) :
    packedInitialState packed (noteCall input + block.val) =
      (List.range 16).map (preparedLane packed input block.val) := by
  apply List.map_congr_left
  intro lane member
  exact accepted_prepared_lane certificate accepted input block
    ⟨lane, List.mem_range.mp member⟩

theorem accepted_first_frame
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) :
    packedInitialState packed (noteCall input) =
      noteFirstFrame (noteWords packed input) := by
  have initial := accepted_initial_state certificate accepted input
    ⟨0, by decide⟩
  simp only [Nat.add_zero] at initial
  rw [initial]
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  by_cases rate : lane < 8
  · have wordBound : lane < 18 := by omega
    change _ = (if lane < 8 then Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd 0
      ((noteWords packed input).getD lane 0) else _)
    rw [if_pos rate, note_words_getD packed input wordBound]
    simp only [preparedLane, ↓reduceIte, rate,
      Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
    exact (Nat.mod_eq_of_lt
      (sponge_source_word_canonical accepted.2.1 (noteCall input) lane)).symm
  · simp [preparedLane, noteConstant, rate]

theorem accepted_middle_frame
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) :
    packedInitialState packed (noteCall input + 1) =
      noteMiddleFrame (noteWords packed input)
        (packedFinalState packed (noteCall input)) := by
  rw [accepted_initial_state certificate accepted input ⟨1, by decide⟩]
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have previous : noteCall input + 1 - 1 = noteCall input := by omega
  by_cases rate : lane < 8
  · have wordBound : 8 + lane < 18 := by omega
    change _ = (if lane < 8 then Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd
      ((packedFinalState packed (noteCall input)).getD lane 0)
      ((noteWords packed input).getD (8 + lane) 0) else _)
    rw [if_pos rate, note_words_getD packed input wordBound,
      final_getD packed _ laneBound]
    simp [preparedLane, rate, wordBound, previous,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldNormalize]
    rfl
  · change _ = (if lane < 8 then _ else
      (packedFinalState packed (noteCall input)).getD lane 0)
    rw [if_neg rate, final_getD packed _ laneBound]
    have previousBound := packed_option_word_canonical accepted
      (hashFinalIndex (noteCall input) lane)
    have previousBoundRelation :
        (packed[hashFinalIndex (noteCall input) lane]?.getD 0) <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
      simpa only [Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus,
        Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus] using
          previousBound
    simp [preparedLane, noteConstant, rate, previous,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldNormalize,
      Nat.mod_eq_of_lt previousBoundRelation]

theorem accepted_last_frame
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) :
    packedInitialState packed (noteCall input + 2) =
      noteLastFrame (noteWords packed input)
        (packedFinalState packed (noteCall input + 1)) := by
  rw [accepted_initial_state certificate accepted input ⟨2, by decide⟩]
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have previous : noteCall input + 2 - 1 = noteCall input + 1 := by omega
  by_cases active : lane < 2
  · have wordBound : 16 + lane < 18 := by omega
    have rate : lane < 8 := by omega
    change _ = (if lane < 2 then Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd
      ((packedFinalState packed (noteCall input + 1)).getD lane 0)
      ((noteWords packed input).getD (16 + lane) 0) else _)
    rw [if_pos active, note_words_getD packed input wordBound,
      final_getD packed _ laneBound]
    simp [preparedLane, rate, wordBound, previous,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldNormalize]
    rfl
  · have outside : ¬16 + lane < 18 := by omega
    change _ = (if lane < 2 then _ else if lane = 11 then
      Hegemon.Transaction.Poseidon2Width16Kernel.fieldAdd
        ((packedFinalState packed (noteCall input + 1)).getD lane 0) 1
      else (packedFinalState packed (noteCall input + 1)).getD lane 0)
    rw [if_neg active, final_getD packed _ laneBound]
    by_cases marker : lane = 11
    · simp [preparedLane, noteConstant, previous, marker,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldNormalize]
      rfl
    · have previousBound := packed_option_word_canonical accepted
        (hashFinalIndex (noteCall input + 1) lane)
      have notActiveWord : ¬ (lane < 8 ∧ 16 + lane < 18) := by omega
      have previousBoundRelation :
          (packed[hashFinalIndex (noteCall input + 1) lane]?.getD 0) <
            Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
        simpa only [Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus,
          Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus] using
            previousBound
      simp [preparedLane, noteConstant, previous, marker, notActiveWord,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldNormalize,
        Nat.mod_eq_of_lt previousBoundRelation]

/-- This is the only nonlinear-provider interface needed by the three-call
note sponge. It follows from the current 332-root recurrence certificate;
no RP03 accepted predicate is present. -/
def FinalStateCorrect (packed : List Nat) : Prop :=
  ∀ call, call < 128 →
    Hegemon.Transaction.Poseidon2Width16Kernel.permutation (packedInitialState packed call) =
      packedFinalState packed call

theorem final_state_of_current_kernel
    {components : RelationProgramComponents}
    (kernel : KernelCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    FinalStateCorrect packed := by
  intro call bound
  exact accepted_hash_call_state kernel accepted bound

theorem accepted_note_digest_eq_exact_commitment
    {components : RelationProgramComponents}
    (certificate : Certificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (finalState : FinalStateCorrect packed)
    (input : Fin 2) :
    (packedFinalState packed (noteCall input + 2)).take digestWords =
      exactV8NoteCommitment (projectNote packed (noteCall input)) := by
  have length : (noteWords packed input).length = 18 :=
    note_words_shape packed input
  have first := finalState (noteCall input) (by
    unfold noteCall; split_ifs <;> omega)
  have middle := finalState (noteCall input + 1) (by
    unfold noteCall; split_ifs <;> omega)
  have last := finalState (noteCall input + 2) (by
    unfold noteCall; split_ifs <;> omega)
  rw [accepted_first_frame certificate accepted input] at first
  rw [accepted_middle_frame certificate accepted input] at middle
  rw [accepted_last_frame certificate accepted input] at last
  have sponge := note_sponge_of_frame_chain (noteWords packed input)
    (packedFinalState packed (noteCall input))
    (packedFinalState packed (noteCall input + 1))
    (packedFinalState packed (noteCall input + 2))
    length (by simp [packedFinalState]) (by simp [packedFinalState])
    first middle last
  rw [← note_words_exact_opening packed input]
    at sponge
  simpa [exactV8NoteCommitment] using sponge.symm

end HegemonCrypto.SmallWood.SmzaRp05NoteSpongeBridge
