import Hegemon.Transaction.Poseidon2V8SemanticSpecification
import Mathlib.Data.List.GetD

namespace HegemonCrypto.SmallWood.V8Smz9FullRateSponge

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

/-- The concrete prepared frame for a full rate-8 block. No short rate block
or extra rate-lane padding is admitted; only the last capacity lane11 is marked. -/
def fullRateFrame (domain : Nat) (inputs : List Nat) (blocks : Nat)
    (state : List Nat) (block : Nat) : List Nat :=
  (List.range 16).map fun lane =>
    let previous := state.getD lane 0
    let seeded := if block = 0 then
      if lane = 8 then domain
      else if lane = 9 then inputs.length
      else if lane = 10 then poseidon2V8SpongeModeMarker
      else if lane = 15 then poseidon2V8SuiteMarker
      else previous
      else previous
    let absorbed := if lane < 8 then
      Poseidon2Width16Kernel.fieldAdd previous (inputs.getD (block * 8 + lane) 0)
      else seeded
    if block + 1 = blocks ∧ lane = 11 then
      Poseidon2Width16Kernel.fieldAdd absorbed 1
    else absorbed

theorem full_rate_absorb_frame (domain : Nat) (inputs state : List Nat)
    (blocks block : Nat) (hinputs : inputs.length = 8 * blocks)
    (hblock : block < blocks) (hstate : state.length = 16) :
    poseidon2V8AbsorbBlock domain inputs blocks state block =
      Poseidon2Width16Kernel.permutation (fullRateFrame domain inputs blocks state block) := by
  have h0 : block * 8 < inputs.length := by omega
  have h1 : block * 8 + 1 < inputs.length := by omega
  have h2 : block * 8 + 2 < inputs.length := by omega
  have h3 : block * 8 + 3 < inputs.length := by omega
  have h4 : block * 8 + 4 < inputs.length := by omega
  have h5 : block * 8 + 5 < inputs.length := by omega
  have h6 : block * 8 + 6 < inputs.length := by omega
  have h7 : block * 8 + 7 < inputs.length := by omega
  conv => lhs; rw [list_sixteen_eq state hstate]
  by_cases first : block = 0
  · subst block
    simp only [Nat.zero_mul, Nat.zero_add] at h0 h1 h2 h3 h4 h5 h6 h7
    by_cases last : 1 = blocks
    · subst blocks
      simp [poseidon2V8AbsorbBlock, poseidon2V8SeedFirstBlock,
        Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate,
        fullRateFrame, List.range_succ, List.getD, h0, h1, h2, h3, h4, h5, h6, h7]
    ·
      simp [poseidon2V8AbsorbBlock, poseidon2V8SeedFirstBlock,
        Poseidon2Width16Kernel.width, Poseidon2Width16Kernel.rate,
        fullRateFrame, last, List.range_succ, List.getD, h0, h1, h2, h3, h4, h5, h6, h7]
  · by_cases last : block + 1 = blocks <;>
      simp [poseidon2V8AbsorbBlock, Poseidon2Width16Kernel.rate,
        fullRateFrame, first, last, List.range_succ, List.getD, h0, h1, h2, h3, h4, h5, h6, h7]

theorem full_rate_block_count (inputs : List Nat) (blocks : Nat)
    (hinputs : inputs.length = 8 * blocks) (positive : 0 < blocks) :
    Nat.max 1 ((inputs.length + Poseidon2Width16Kernel.rate - 1) /
      Poseidon2Width16Kernel.rate) = blocks := by
  change Nat.max 1 ((inputs.length + 8 - 1) / 8) = blocks
  have quotient : (inputs.length + 8 - 1) / 8 = blocks := by omega
  rw [quotient]
  exact Nat.max_eq_right (by omega)

/-- Every step is the exact permutation of its concrete frame. This pure fold
lemma contains no source-row premise; consumers must discharge each equation
from the corresponding admitted source relation. -/
theorem full_rate_sponge_of_frame_chain (domain : Nat) (inputs : List Nat)
    (blocks : Nat) (states : Nat → List Nat)
    (hinputs : inputs.length = 8 * blocks) (positive : 0 < blocks)
    (initial : states 0 = poseidon2V8InitialState)
    (lengths : ∀ block, block < blocks → (states block).length = 16)
    (equations : ∀ block, block < blocks →
      Poseidon2Width16Kernel.permutation
        (fullRateFrame domain inputs blocks (states block) block) = states (block + 1)) :
    poseidon2V8Sponge domain inputs = (states blocks).take digestWords := by
  have fold : ∀ n, n ≤ blocks →
      (List.range n).foldl (poseidon2V8AbsorbBlock domain inputs blocks)
        poseidon2V8InitialState = states n := by
    intro n
    induction n with
    | zero => intro _; simpa using initial.symm
    | succ n ih =>
      intro bound
      have step : n < blocks := by omega
      rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
        ih (by omega), full_rate_absorb_frame domain inputs (states n) blocks n
          hinputs step (lengths n step)]
      exact equations n step
  unfold poseidon2V8Sponge
  rw [full_rate_block_count inputs blocks hinputs positive]
  dsimp only
  rw [fold blocks (Nat.le_refl blocks)]


end HegemonCrypto.SmallWood.V8Smz9FullRateSponge
