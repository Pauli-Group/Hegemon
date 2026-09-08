import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import Mathlib.Data.List.GetD

namespace HegemonCrypto.SmallWood.V8Smz9AccumulatorSponge

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

def accumulatorFirstFrame (inputs : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 8 then Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0)
    else if lane = 8 then 6
    else if lane = 9 then 23
    else if lane = 10 then poseidon2V8SpongeModeMarker
    else if lane = 15 then poseidon2V8SuiteMarker
    else 0

def accumulatorMiddleFrame (inputs state : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 8 then
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (8 + lane) 0)
    else state.getD lane 0

/-- Seven inputs fill lanes0..6; lane7 remains unchanged. The exact semantic
sponge places its final marker solely at capacity lane11. -/
def accumulatorLastFrame (inputs state : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 7 then
      Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (16 + lane) 0)
    else if lane = 11 then Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) 1
    else state.getD lane 0

theorem accumulator_absorb_first (inputs : List Nat) (hinputs : inputs.length = 23) :
    poseidon2V8AbsorbBlock poseidon2V8AccumulatorDomain inputs 3 poseidon2V8InitialState 0 =
      Poseidon2Width16Kernel.permutation (accumulatorFirstFrame inputs) := by
  simp [poseidon2V8AbsorbBlock, poseidon2V8InitialState, poseidon2V8SeedFirstBlock,
    poseidon2V8AccumulatorDomain, Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate,
    hinputs, accumulatorFirstFrame, List.range_succ, List.replicate_succ, List.getD]

theorem accumulator_absorb_middle (inputs state : List Nat)
    (hinputs : inputs.length = 23) (hstate : state.length = 16) :
    poseidon2V8AbsorbBlock poseidon2V8AccumulatorDomain inputs 3 state 1 =
      Poseidon2Width16Kernel.permutation (accumulatorMiddleFrame inputs state) := by
  conv => lhs; rw [list_sixteen_eq state hstate]
  simp [poseidon2V8AbsorbBlock, Poseidon2Width16Kernel.rate, hinputs, accumulatorMiddleFrame,
    List.range_succ, List.getD]

theorem accumulator_absorb_last (inputs state : List Nat)
    (hinputs : inputs.length = 23) (hstate : state.length = 16) :
    poseidon2V8AbsorbBlock poseidon2V8AccumulatorDomain inputs 3 state 2 =
      Poseidon2Width16Kernel.permutation (accumulatorLastFrame inputs state) := by
  conv => lhs; rw [list_sixteen_eq state hstate]
  simp [poseidon2V8AbsorbBlock, Poseidon2Width16Kernel.rate, hinputs, accumulatorLastFrame,
    List.range_succ, List.getD]

theorem accumulator_sponge_three_blocks (inputs : List Nat) (hinputs : inputs.length = 23) :
    poseidon2V8Sponge poseidon2V8AccumulatorDomain inputs =
      (poseidon2V8AbsorbBlock poseidon2V8AccumulatorDomain inputs 3
        (poseidon2V8AbsorbBlock poseidon2V8AccumulatorDomain inputs 3
          (poseidon2V8AbsorbBlock poseidon2V8AccumulatorDomain inputs 3
            poseidon2V8InitialState 0) 1) 2).take digestWords := by
  simp [poseidon2V8Sponge, hinputs, Poseidon2Width16Kernel.rate, List.range_succ]

theorem accumulator_sponge_of_frame_chain (inputs first middle last : List Nat)
    (hinputs : inputs.length = 23) (hfirst : first.length = 16) (hmiddle : middle.length = 16)
    (firstEquation : Poseidon2Width16Kernel.permutation (accumulatorFirstFrame inputs) = first)
    (middleEquation : Poseidon2Width16Kernel.permutation (accumulatorMiddleFrame inputs first) = middle)
    (lastEquation : Poseidon2Width16Kernel.permutation (accumulatorLastFrame inputs middle) = last) :
    poseidon2V8Sponge poseidon2V8AccumulatorDomain inputs = last.take digestWords := by
  rw [accumulator_sponge_three_blocks inputs hinputs, accumulator_absorb_first inputs hinputs,
    firstEquation, accumulator_absorb_middle inputs first hinputs hfirst,
    middleEquation, accumulator_absorb_last inputs middle hinputs hmiddle, lastEquation]

theorem accumulator_digest_of_frame_chain (opening : V8AccumulatorOpening) (first middle last : List Nat)
    (hinputs : (exactV8AccumulatorWords opening).length = 23)
    (hfirst : first.length = 16) (hmiddle : middle.length = 16)
    (firstEquation : Poseidon2Width16Kernel.permutation (accumulatorFirstFrame (exactV8AccumulatorWords opening)) = first)
    (middleEquation : Poseidon2Width16Kernel.permutation (accumulatorMiddleFrame (exactV8AccumulatorWords opening) first) = middle)
    (lastEquation : Poseidon2Width16Kernel.permutation (accumulatorLastFrame (exactV8AccumulatorWords opening) middle) = last) :
    exactV8AccumulatorDigest opening = last.take digestWords :=
  accumulator_sponge_of_frame_chain _ _ _ _ hinputs hfirst hmiddle firstEquation middleEquation lastEquation


end HegemonCrypto.SmallWood.V8Smz9AccumulatorSponge
