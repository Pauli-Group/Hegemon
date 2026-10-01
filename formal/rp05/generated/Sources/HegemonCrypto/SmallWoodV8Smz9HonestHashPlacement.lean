import HegemonCrypto.SmallWoodV8Smz9HonestHashMaterialization

/-! Placement of the completed hash block at its actual full-relation coordinates.
Prefix and suffix words remain arbitrary caller data; this is not a full lowerer.
The source-owned initial/final index functions are reused unchanged.
-/

namespace HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization

open Hegemon.Transaction
open Poseidon2V8ConstraintRefinement

set_option maxRecDepth 10000
set_option maxHeartbeats 600000
set_option Elab.async false

theorem rectangular_flatten_length (rows : List (List Nat)) (columns : Nat)
    (shape : ∀ row, row ∈ rows → row.length = columns) :
    rows.flatten.length = rows.length * columns := by
  induction rows with
  | nil => simp
  | cons head tail ih =>
      have headLength := shape head (by simp)
      have tailShape := fun row member => shape row (List.mem_cons_of_mem head member)
      simp only [List.flatten_cons, List.length_append, List.length_cons,
        headLength, ih tailShape, Nat.add_mul, Nat.one_mul]
      omega

theorem rectangular_flatten_getD (rows : List (List Nat)) (columns row lane : Nat)
    (shape : ∀ entry, entry ∈ rows → entry.length = columns)
    (rowBound : row < rows.length) (laneBound : lane < columns) :
    rows.flatten.getD (row * columns + lane) 0 = (rows.getD row []).getD lane 0 := by
  induction rows generalizing row with
  | nil => simp at rowBound
  | cons head tail ih =>
      have headLength := shape head (by simp)
      have tailShape := fun entry member => shape entry (List.mem_cons_of_mem head member)
      cases row with
      | zero =>
          simp only [Nat.zero_mul, Nat.zero_add, List.flatten_cons, List.getD_cons_zero]
          exact getD_append_left head tail.flatten lane (by omega)
      | succ row =>
          have offset : (row + 1) * columns + lane = head.length + (row * columns + lane) := by
            rw [headLength, Nat.add_mul, Nat.one_mul]
            omega
          simp only [List.flatten_cons, List.getD_cons_succ, offset, getD_append_offset]
          exact ih row tailShape (by simpa using rowBound)

def placeHashBlock (leading : List Nat) (live : LiveInitialStates) (suffix : List Nat) : List Nat :=
  leading ++ (hashRows live).flatten ++ suffix

theorem hash_flat_length (live : LiveInitialStates) : (hashRows live).flatten.length = 23296 := by
  rw [rectangular_flatten_length (hashRows live) 64 (hash_rows_shape live).2, (hash_rows_shape live).1]

theorem placed_length (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (suffixLength : suffix.length = 2496) :
    (placeHashBlock leading live suffix).length = 43904 := by
  simp only [placeHashBlock, List.length_append, prefixLength, hash_flat_length, suffixLength]

theorem placed_hash_word (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (row lane : Nat)
    (rowBound : row < 364) (laneBound : lane < 64) :
    (placeHashBlock leading live suffix).getD (18112 + (row * 64 + lane)) 0 =
      packedHashValue (hashRows live) row lane := by
  have indexBound : row * 64 + lane < (hashRows live).flatten.length := by
    rw [hash_flat_length]
    omega
  have result := three_piece_wire leading (hashRows live).flatten suffix
    (row * 64 + lane) indexBound
  rw [prefixLength, rectangular_flatten_getD (hashRows live) 64 row lane
    (hash_rows_shape live).2 (by rw [(hash_rows_shape live).1]; exact rowBound) laneBound] at result
  exact result

theorem placed_initial_at_decoder_index (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (call word : Nat)
    (callBound : call < 128) (wordBound : word < 16) :
    (placeHashBlock leading live suffix).getD
        (Poseidon2V8DecoderRefinement.hashInitialIndex call word) 0 =
      (callInitial live call).getD word 0 := by
  have coordinate : Poseidon2V8DecoderRefinement.hashInitialIndex call word =
      18112 + ((call / 64 * 182 + word) * 64 + call % 64) := by
    simp only [Poseidon2V8DecoderRefinement.hashInitialIndex, Poseidon2V8DecoderRefinement.hashRowStart,
      Poseidon2V8DecoderRefinement.packingFactor, Poseidon2V8DecoderRefinement.hashRowsPerGroup]
    omega
  rw [coordinate, placed_hash_word leading suffix live prefixLength _ _ (by omega) (by omega)]
  change packedHashValue (hashRows live) (hashInitialLocalRow (call / 64) word) (call % 64) = _
  rw [hash_initial_word live _ _ _ (by omega) (by omega) wordBound]
  have recombined : call / 64 * 64 + call % 64 = call := by omega
  rw [recombined]

theorem placed_wire_at_source_index (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (call wire : Nat)
    (callBound : call < 128) (wireBound : wire < 150) :
    (placeHashBlock leading live suffix).getD
        (packedWitnessIndex (hashSboxWireRelationRow (hashCallGroup call) wire) (hashCallLane call)) 0 =
      (Poseidon2Width16Kernel.compressedTrace (callInitial live call)).wires.getD wire 0 := by
  have coordinate : packedWitnessIndex (hashSboxWireRelationRow (hashCallGroup call) wire) (hashCallLane call) =
      18112 + ((call / 64 * 182 + (16 + wire)) * 64 + call % 64) := by
    simp only [packedWitnessIndex, hashSboxWireRelationRow, hashSboxWireLocalRow, hashGroupLocalRowStart,
      hashCallGroup, hashCallLane, hashRowStart, packingFactor, hashRowsPerGroup,
      Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.sboxWiresPerCall,
      Poseidon2Width16Kernel.externalRoundsPerHalf, Poseidon2Width16Kernel.internalRounds]
    omega
  rw [coordinate, placed_hash_word leading suffix live prefixLength _ _ (by omega) (by omega)]
  have localRow : call / 64 * 182 + (16 + wire) = hashSboxWireLocalRow (call / 64) wire := by
    simp only [hashSboxWireLocalRow, hashGroupLocalRowStart, hashRowsPerGroup,
      Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.sboxWiresPerCall,
      Poseidon2Width16Kernel.externalRoundsPerHalf, Poseidon2Width16Kernel.internalRounds]
    omega
  rw [localRow, hash_wire_word live _ _ _ (by omega) (by omega) wireBound]
  have recombined : call / 64 * 64 + call % 64 = call := by omega
  rw [recombined]

theorem placed_final_at_decoder_index (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (call word : Nat)
    (callBound : call < 128) (wordBound : word < 16) :
    (placeHashBlock leading live suffix).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex call word) 0 =
      (Poseidon2Width16Kernel.permutation (callInitial live call)).getD word 0 := by
  have coordinate : Poseidon2V8DecoderRefinement.hashFinalIndex call word =
      18112 + ((call / 64 * 182 + (166 + word)) * 64 + call % 64) := by
    unfold Poseidon2V8DecoderRefinement.hashFinalIndex Poseidon2V8DecoderRefinement.hashRowStart
      Poseidon2V8DecoderRefinement.packingFactor Poseidon2V8DecoderRefinement.hashRowsPerGroup
      Poseidon2V8DecoderRefinement.hashFinalRowOffset
    omega
  rw [coordinate, placed_hash_word leading suffix live prefixLength _ _ (by omega) (by omega)]
  have localRow : call / 64 * 182 + (166 + word) = hashFinalLocalRow (call / 64) word := by
    simp only [hashFinalLocalRow, hashGroupLocalRowStart, hashRowsPerGroup,
      Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.sboxWiresPerCall,
      Poseidon2Width16Kernel.externalRoundsPerHalf, Poseidon2Width16Kernel.internalRounds]
    omega
  rw [localRow, hash_final_word live _ _ _ (by omega) (by omega) wordBound]
  have recombined : call / 64 * 64 + call % 64 = call := by omega
  rw [recombined, Poseidon2Width16Kernel.compressed_trace_final_state]

theorem placed_live_initial (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (call : Fin 125) (word : Fin 16) :
    (placeHashBlock leading live suffix).getD
        (Poseidon2V8DecoderRefinement.hashInitialIndex call.val word.val) 0 = (live call word).val := by
  rw [placed_initial_at_decoder_index leading suffix live prefixLength _ _ (by omega) word.isLt,
    call_initial_live]

/-- All 48 source dummy-initial coordinates are zero, with no full acceptance premise. -/
theorem placed_dummy_initial_zero (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (call word : Nat)
    (dummy : 125 ≤ call) (callBound : call < 128) (wordBound : word < 16) :
    (placeHashBlock leading live suffix).getD
        (Poseidon2V8DecoderRefinement.hashInitialIndex call word) 0 = 0 := by
  rw [placed_initial_at_decoder_index leading suffix live prefixLength call word callBound wordBound,
    call_initial_dummy live call dummy]
  simp only [List.getD_eq_getElem?_getD, List.getElem?_replicate, if_pos wordBound, Option.getD_some]

/-- Dummy output is the actual zero-input permutation, not a zero-filled block. -/
theorem placed_dummy_final_first_word (leading suffix : List Nat) (live : LiveInitialStates)
    (prefixLength : leading.length = 18112) (call : Nat)
    (dummy : 125 ≤ call) (callBound : call < 128) :
    (placeHashBlock leading live suffix).getD
        (Poseidon2V8DecoderRefinement.hashFinalIndex call 0) 0 = 0x60cffc11a095a4f6 := by
  rw [placed_final_at_decoder_index leading suffix live prefixLength call 0 callBound (by decide),
    call_initial_dummy live call dummy]
  have known := congrArg (fun words : List Nat => words.getD 0 0)
    Poseidon2Width16Kernel.zero_state_permutation_known_answer
  simpa only [Poseidon2Width16Kernel.width, List.getD_cons_zero] using known


end HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
