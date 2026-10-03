import HegemonCrypto.SmallWoodV8Smz9FullRateSponge
import HegemonCrypto.SmallWoodV8Smz9FullRateSourceFrames

namespace HegemonCrypto.SmallWood.V8Smz9FullRateSourceComposition

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldAdd)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes
open HegemonCrypto.SmallWood.V8Smz9FullRateSponge
open HegemonCrypto.SmallWood.V8Smz9FullRateSourceFrames

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

def fullRateSourceWords (packed : List Nat) (kind : Nat) : List Nat :=
  (List.range (8 * fullRateSourceBlocks kind)).map (spongeSourceWord packed (fullRateSourceCall kind))

def fullRateSourceState (packed : List Nat) (kind state : Nat) : List Nat :=
  if state = 0 then poseidon2V8InitialState
  else packedFinalState packed (fullRateSourceCall kind + state - 1)

def fullRatePreparedLane (packed : List Nat) (kind block lane : Nat) : Nat :=
  if block = 0 then
    if lane < 8 then spongeSourceWord packed (fullRateSourceCall kind) lane
    else fullRateFrameConstant kind block lane
  else if lane < 8 then
    fieldAdd (packedWord packed (hashFinalIndex (fullRateSourceCall kind + block - 1) lane))
      (spongeSourceWord packed (fullRateSourceCall kind) (block * 8 + lane))
  else fieldAdd (packedWord packed (hashFinalIndex (fullRateSourceCall kind + block - 1) lane))
    (fullRateFrameConstant kind block lane)

theorem full_rate_source_bounds (kind : Fin 2) :
    1 < fullRateSourceBlocks kind.val ∧ fullRateSourceBlocks kind.val ≤ 15 ∧
      fullRateSourceCall kind.val + fullRateSourceBlocks kind.val ≤ 128 := by
  fin_cases kind <;> decide

theorem full_rate_source_words_getD (packed : List Nat) (kind : Nat) {word : Nat}
    (bound : word < 8 * fullRateSourceBlocks kind) :
    (fullRateSourceWords packed kind).getD word 0 = spongeSourceWord packed (fullRateSourceCall kind) word := by
  simp [fullRateSourceWords, List.getD_eq_getElem?_getD, bound]

theorem accepted_full_rate_prepared_state {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (kind : Fin 2) {block : Nat} (within : block < fullRateSourceBlocks kind.val) :
    packedInitialState packed (fullRateSourceCall kind.val + block) =
      (List.range 16).map (fullRatePreparedLane packed kind.val block) := by
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  by_cases rate : lane < 8
  · have source := accepted_note_absorbed_coordinate accepted (fullRateSourceCall kind.val) block lane rate
    by_cases first : block = 0
    · simpa only [fullRatePreparedLane, first, if_true, if_pos rate, Nat.zero_mul, Nat.zero_add] using source
    · simpa only [fullRatePreparedLane, first, if_false, if_pos rate] using source
  · have index : 8 + (lane - 8) = lane := by omega
    have source := accepted_full_rate_frame_coordinate accepted kind
      ⟨block, by have := (full_rate_source_bounds kind).2.1; omega⟩
      ⟨lane - 8, by omega⟩ within
    rw [index] at source
    simpa only [fullRatePreparedLane, if_neg rate] using source

theorem accepted_full_rate_initial_frame {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (kind : Fin 2) {block : Nat} (within : block < fullRateSourceBlocks kind.val) :
    packedInitialState packed (fullRateSourceCall kind.val + block) =
      fullRateFrame (fullRateSourceDomain kind.val) (fullRateSourceWords packed kind.val)
        (fullRateSourceBlocks kind.val) (fullRateSourceState packed kind.val block) block := by
  rw [accepted_full_rate_prepared_state accepted kind within]
  apply List.map_congr_left
  intro lane member
  have laneBound := List.mem_range.mp member
  have length : (fullRateSourceWords packed kind.val).length = 8 * fullRateSourceBlocks kind.val := by
    simp [fullRateSourceWords]
  by_cases first : block = 0
  · have notLast : 0 + 1 ≠ fullRateSourceBlocks kind.val := by
      have := (full_rate_source_bounds kind).1
      omega
    have previous : (fullRateSourceState packed kind.val block).getD lane 0 = 0 := by
      rw [fullRateSourceState, if_pos first]
      have checked : ∀ lane : Fin 16, poseidon2V8InitialState.getD lane.val 0 = 0 := by decide
      exact checked ⟨lane, laneBound⟩
    simp only [first] at previous
    simp only [first, previous, if_true, length, notLast,
      false_and, if_false, fullRatePreparedLane, Nat.zero_mul, Nat.zero_add]
    by_cases rate : lane < 8
    · rw [if_pos rate, if_pos rate, full_rate_source_words_getD packed kind.val (by
        have := (full_rate_source_bounds kind).1; omega)]
      simp only [Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
      exact (Nat.mod_eq_of_lt (sponge_source_word_canonical accepted.2.1 _ _)).symm
    · simp only [if_neg rate, fullRateFrameConstant, if_true]
  · have previous : (fullRateSourceState packed kind.val block).getD lane 0 =
        packedWord packed (hashFinalIndex (fullRateSourceCall kind.val + block - 1) lane) := by
      rw [fullRateSourceState, if_neg first, packed_final_getD packed _ laneBound]
    simp only [previous, if_neg first, fullRatePreparedLane]
    by_cases rate : lane < 8
    · have notMarker : ¬(block + 1 = fullRateSourceBlocks kind.val ∧ lane = 11) := by omega
      rw [if_neg notMarker, if_pos rate, if_pos rate,
        full_rate_source_words_getD packed kind.val (by omega)]
      rfl
    · rw [if_neg rate, if_neg rate]
      simp only [fullRateFrameConstant, if_neg first]
      by_cases marker : block + 1 = fullRateSourceBlocks kind.val ∧ lane = 11
      · simp only [if_pos marker]
        rfl
      · simp only [if_neg marker, fieldAdd, Nat.add_zero]
        exact Nat.mod_eq_of_lt (packed_word_canonical accepted.2.1 _)

/-- Both full-rate source hash chains compute the exact semantic sponge of
their source-projected words; later endpoints identify those words with public
intent projection or the typed policy opening. -/
theorem accepted_full_rate_sponge_digest {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (kind : Fin 2) :
    (packedFinalState packed
      (fullRateSourceCall kind.val + fullRateSourceBlocks kind.val - 1)).take digestWords =
      poseidon2V8Sponge (fullRateSourceDomain kind.val) (fullRateSourceWords packed kind.val) := by
  have positive : 0 < fullRateSourceBlocks kind.val := by
    have := (full_rate_source_bounds kind).1; omega
  have composition := full_rate_sponge_of_frame_chain (fullRateSourceDomain kind.val)
    (fullRateSourceWords packed kind.val) (fullRateSourceBlocks kind.val)
    (fullRateSourceState packed kind.val) (by simp [fullRateSourceWords]) positive
    (by simp [fullRateSourceState])
    (by intro block _; unfold fullRateSourceState; split <;>
      simp [poseidon2V8InitialState, Poseidon2Width16Kernel.width, packedFinalState])
    (by
      intro block within
      have callBound : fullRateSourceCall kind.val + block < 128 := by
        have := (full_rate_source_bounds kind).2.2; omega
      have next : fullRateSourceState packed kind.val (block + 1) =
          packedFinalState packed (fullRateSourceCall kind.val + block) := by
        simp only [fullRateSourceState, Nat.add_eq_zero_iff, Nat.one_ne_zero, and_false, if_false]
        congr 1
      rw [next, ← accepted_full_rate_initial_frame accepted kind within]
      exact (accepted_final_state_eq_kernel accepted callBound).symm)
  have nonzero : fullRateSourceBlocks kind.val ≠ 0 := by omega
  simpa only [fullRateSourceState, if_neg nonzero] using composition.symm


end HegemonCrypto.SmallWood.V8Smz9FullRateSourceComposition
