import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import Mathlib.Data.List.GetD

namespace HegemonCrypto.SmallWood.V8Smz9ValueLockSponge

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


def valueLockFirstFrame (inputs : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 8 then Poseidon2Width16Kernel.fieldAdd 0 (inputs.getD lane 0)
    else if lane = 8 then 8
    else if lane = 9 then 14
    else if lane = 10 then poseidon2V8SpongeModeMarker
    else if lane = 15 then poseidon2V8SuiteMarker
    else 0

def valueLockLastFrame (inputs state : List Nat) : List Nat :=
  (List.range 16).map fun lane =>
    if lane < 6 then Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) (inputs.getD (8 + lane) 0)
    else if lane = 11 then Poseidon2Width16Kernel.fieldAdd (state.getD lane 0) 1
    else state.getD lane 0

theorem value_lock_absorb_first (inputs : List Nat) (hinputs : inputs.length = 14) :
    poseidon2V8AbsorbBlock poseidon2V8ValueLockDomain inputs 2 poseidon2V8InitialState 0 =
      Poseidon2Width16Kernel.permutation (valueLockFirstFrame inputs) := by
  simp [poseidon2V8AbsorbBlock, poseidon2V8InitialState, poseidon2V8SeedFirstBlock,
    poseidon2V8ValueLockDomain, Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate,
    hinputs, valueLockFirstFrame, List.range_succ, List.replicate_succ, List.getD]

theorem value_lock_absorb_last (inputs state : List Nat)
    (hinputs : inputs.length = 14) (hstate : state.length = 16) :
    poseidon2V8AbsorbBlock poseidon2V8ValueLockDomain inputs 2 state 1 =
      Poseidon2Width16Kernel.permutation (valueLockLastFrame inputs state) := by
  conv => lhs; rw [list_sixteen_eq state hstate]
  simp [poseidon2V8AbsorbBlock, Poseidon2Width16Kernel.rate, hinputs, valueLockLastFrame,
    List.range_succ, List.getD]

theorem value_lock_sponge_of_frame_chain (inputs first last : List Nat)
    (hinputs : inputs.length = 14) (hfirst : first.length = 16)
    (firstEquation : Poseidon2Width16Kernel.permutation (valueLockFirstFrame inputs) = first)
    (lastEquation : Poseidon2Width16Kernel.permutation (valueLockLastFrame inputs first) = last) :
    poseidon2V8Sponge poseidon2V8ValueLockDomain inputs = last.take digestWords := by
  have expanded : poseidon2V8Sponge poseidon2V8ValueLockDomain inputs =
      (poseidon2V8AbsorbBlock poseidon2V8ValueLockDomain inputs 2
        (poseidon2V8AbsorbBlock poseidon2V8ValueLockDomain inputs 2 poseidon2V8InitialState 0) 1).take digestWords := by
    simp [poseidon2V8Sponge, hinputs, Poseidon2Width16Kernel.rate, List.range_succ]
  rw [expanded, value_lock_absorb_first inputs hinputs, firstEquation,
    value_lock_absorb_last inputs first hinputs hfirst, lastEquation]


end HegemonCrypto.SmallWood.V8Smz9ValueLockSponge
