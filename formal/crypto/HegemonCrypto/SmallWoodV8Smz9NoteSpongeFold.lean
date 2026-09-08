import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import Mathlib.Data.List.GetD

namespace HegemonCrypto.SmallWood.V8Smz9NoteSpongeFold

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option maxHeartbeats 1000000
set_option maxRecDepth 100000

private theorem list_sixteen_eq (state : List Nat) (hstate : state.length = 16) :
    state = [state.getD 0 0, state.getD 1 0, state.getD 2 0, state.getD 3 0,
      state.getD 4 0, state.getD 5 0, state.getD 6 0, state.getD 7 0,
      state.getD 8 0, state.getD 9 0, state.getD 10 0, state.getD 11 0,
      state.getD 12 0, state.getD 13 0, state.getD 14 0, state.getD 15 0] := by
  have remap : state = (List.range 16).map (fun lane => state.getD lane 0) := by
    apply List.ext_getElem (by simp [hstate])
    intro i hi hi'
    simp only [List.getElem_map, List.getElem_range]
    exact (List.getD_eq_getElem state 0 hi).symm
  simpa only [List.range_succ, List.range_zero, List.map_append, List.map_cons,
    List.map_nil, List.nil_append, List.append_assoc, List.cons_append] using remap

def noteFirstFrame (inputs : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 8 then Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0)
    else if lane = 8 then 1
    else if lane = 9 then 18
    else if lane = 10 then poseidon2V8SpongeModeMarker
    else if lane = 15 then poseidon2V8SuiteMarker
    else 0

def noteMiddleFrame (inputs state : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 8 then
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (8 + lane) 0)
    else state.getD lane 0

def noteLastFrame (inputs state : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 2 then
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (16 + lane) 0)
    else if lane = 11 then Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) 1
    else state.getD lane 0

theorem note_first_frame_canonical (inputs : List Nat)
    (canonical : ∀ lane, lane < 8 → inputs.getD lane 0 < Poseidon2Width16Kernel.fieldModulus) :
    noteFirstFrame inputs =
      (List.range 16).map (fun lane =>
        if lane < 8 then inputs.getD lane 0
        else if lane = 8 then 1
        else if lane = 9 then 18
        else if lane = 10 then poseidon2V8SpongeModeMarker
        else if lane = 15 then poseidon2V8SuiteMarker
        else 0) := by
  apply List.map_congr_left
  intro lane member
  by_cases rate : lane < 8
  · simp only [if_pos rate, Poseidon2Width16Kernel.fieldAdd, Nat.zero_add]
    exact Nat.mod_eq_of_lt (canonical lane rate)
  · simp [rate]

theorem note_absorb_first (inputs : List Nat) (hinputs : inputs.length = 18) :
    poseidon2V8AbsorbBlock poseidon2V8NoteDomain inputs 3 poseidon2V8InitialState 0 =
      Poseidon2Width16Kernel.permutation (noteFirstFrame inputs) := by
  simp [poseidon2V8AbsorbBlock, poseidon2V8InitialState, poseidon2V8SeedFirstBlock,
    poseidon2V8NoteDomain, Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate,
    hinputs, noteFirstFrame, List.range_succ, List.replicate_succ,
    List.getD]

theorem note_absorb_middle (inputs state : List Nat)
    (hinputs : inputs.length = 18) (hstate : state.length = 16) :
    poseidon2V8AbsorbBlock poseidon2V8NoteDomain inputs 3 state 1 =
      Poseidon2Width16Kernel.permutation (noteMiddleFrame inputs state) := by
  conv => lhs; rw [list_sixteen_eq state hstate]
  simp [poseidon2V8AbsorbBlock, Poseidon2Width16Kernel.rate, hinputs, noteMiddleFrame,
    List.range_succ, List.getD]

theorem note_absorb_last (inputs state : List Nat)
    (hinputs : inputs.length = 18) (hstate : state.length = 16) :
    poseidon2V8AbsorbBlock poseidon2V8NoteDomain inputs 3 state 2 =
      Poseidon2Width16Kernel.permutation (noteLastFrame inputs state) := by
  conv => lhs; rw [list_sixteen_eq state hstate]
  simp [poseidon2V8AbsorbBlock, Poseidon2Width16Kernel.rate, hinputs, noteLastFrame,
    List.range_succ, List.getD]

/-- The exact semantic 18-word sponge has precisely the three source calls. -/
theorem note_sponge_three_blocks (inputs : List Nat) (hinputs : inputs.length = 18) :
    poseidon2V8Sponge poseidon2V8NoteDomain inputs =
      (poseidon2V8AbsorbBlock poseidon2V8NoteDomain inputs 3
        (poseidon2V8AbsorbBlock poseidon2V8NoteDomain inputs 3
          (poseidon2V8AbsorbBlock poseidon2V8NoteDomain inputs 3
            poseidon2V8InitialState 0) 1) 2).take digestWords := by
  simp [poseidon2V8Sponge, hinputs, Poseidon2Width16Kernel.rate,
    List.range_succ]

/-- Composition consumes the actual three permutation equations and exposes the
exact semantic digest. Each premise names one concrete prepared source frame. -/
theorem note_sponge_of_frame_chain (inputs first middle last : List Nat)
    (hinputs : inputs.length = 18) (hfirst : first.length = 16)
    (hmiddle : middle.length = 16)
    (firstEquation : Poseidon2Width16Kernel.permutation (noteFirstFrame inputs) = first)
    (middleEquation : Poseidon2Width16Kernel.permutation (noteMiddleFrame inputs first) = middle)
    (lastEquation : Poseidon2Width16Kernel.permutation (noteLastFrame inputs middle) = last) :
    poseidon2V8Sponge poseidon2V8NoteDomain inputs = last.take digestWords := by
  rw [note_sponge_three_blocks inputs hinputs, note_absorb_first inputs hinputs,
    firstEquation, note_absorb_middle inputs first hinputs hfirst,
    middleEquation, note_absorb_last inputs middle hinputs hmiddle, lastEquation]

end HegemonCrypto.SmallWood.V8Smz9NoteSpongeFold
