import HegemonCrypto.NativePrivateSpendSpongeBridge
import Hegemon.Transaction.Poseidon2V8SemanticSpecification

/-! Pure short-block absorption and countdown/fold transport. Uncompiled.
The generic initial-seed join is not claimed by these component lemmas. -/
namespace HegemonCrypto.NativePrivateSpendGenericSpongeAbsorption
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open NativePrivateSpendSpongeBridge
set_option autoImplicit false

def lanes (f : Nat → Nat) : List Nat := (List.range 16).map f

theorem lanes_getD (f : Nat → Nat) (i : Nat) (hi : i < 16) :
    (lanes f).getD i 0 = f i := by
  simp only [lanes, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range hi, Option.map_some, Option.getD_some]

theorem lanes_set (f : Nat → Nat) (i value : Nat) (hi : i < 16) :
    (lanes f).set i value = lanes (fun j => if j = i then value else f j) := by
  apply List.ext_getElem (by simp [lanes])
  intro j hj hj'
  by_cases same : j = i
  · subst j
    rw [List.getElem_set_self (by simpa [lanes] using hi)]
    simp [lanes]
  · simp only [List.getElem_set, lanes, List.getElem_map, List.getElem_range]
    simp [same, Ne.symm same]

theorem lanes_remap (state : List Nat) (shape : state.length = 16) :
    state = lanes (fun i => state.getD i 0) := by
  apply List.ext_getElem (by simp [lanes, shape])
  intro i hi hi'
  simp only [lanes, List.getElem_map, List.getElem_range]
  exact List.getElem_eq_getD (h := hi) 0

/-- No full-block premise: each lane is independently skipped beyond length. -/
def absorbStep (inputs : List Nat) (block : Nat) (state : List Nat) (lane : Nat) : List Nat :=
  if block*8+lane < inputs.length then
    state.set lane (Poseidon2Width16Kernel.fieldAdd
      (state.getD lane 0) (inputs.getD (block*8+lane) 0))
  else state

theorem partial_absorption (inputs : List Nat) (block n : Nat) (f : Nat → Nat)
    (hn : n ≤ 8) :
    (List.range n).foldl (absorbStep inputs block) (lanes f) =
      lanes (fun j => if j < n ∧ block*8+j < inputs.length then
        Poseidon2Width16Kernel.fieldAdd (f j) (inputs.getD (block*8+j) 0) else f j) := by
  induction n with
  | zero => simp [lanes]
  | succ n ih =>
    have bound : n < 16 := by omega
    rw [List.range_succ, List.foldl_append, List.foldl_cons, List.foldl_nil,
      ih (by omega)]
    unfold absorbStep
    by_cases occupied : block*8+n < inputs.length
    · rw [if_pos occupied, lanes_getD _ n bound, lanes_set _ n _ bound]
      apply congrArg lanes
      funext j
      by_cases same : j = n
      · subst j; simp [occupied]
      · by_cases earlier : j < n
        · have next : j < n+1 := by omega
          simp [same, earlier, next]
        · have later : ¬ j < n+1 := by omega
          simp [same, earlier, later]
    · rw [if_neg occupied]
      apply congrArg lanes
      funext j
      by_cases same : j = n
      · subst j; simp [occupied]
      · have sameBound : (j < n+1) = (j < n) := by
          apply propext; omega
        simp only [sameBound]

/-- Pointwise frame with the fixed evaluator's first-block seeding. -/
def genericFrame (domain : Nat) (inputs state : List Nat) (total block : Nat) : List Nat :=
  let seeded := if block = 0 then poseidon2V8SeedFirstBlock domain inputs.length state else state
  lanes (fun lane =>
    if lane < 8 ∧ block*8+lane < inputs.length then
      Poseidon2Width16Kernel.fieldAdd (seeded.getD lane 0) (inputs.getD (block*8+lane) 0)
    else if lane = 11 ∧ block+1 = total then
      Poseidon2Width16Kernel.fieldAdd (seeded.getD lane 0) 1
    else seeded.getD lane 0)

/-- General replacement for full_rate_absorb_frame, including short/empty blocks. -/
theorem generic_absorb_frame (domain : Nat) (inputs state : List Nat)
    (total block : Nat) (shape : state.length = 16) :
    poseidon2V8AbsorbBlock domain inputs total state block =
      Poseidon2Width16Kernel.permutation (genericFrame domain inputs state total block) := by
  let seeded := if block = 0 then poseidon2V8SeedFirstBlock domain inputs.length state else state
  have seededShape : seeded.length = 16 := by
    dsimp only [seeded]
    split
    · simp only [poseidon2V8SeedFirstBlock, List.length_set, shape]
    · exact shape
  have absorbed : (List.range 8).foldl (absorbStep inputs block) seeded =
      lanes (fun j => if j < 8 ∧ block*8+j < inputs.length then
        Poseidon2Width16Kernel.fieldAdd (seeded.getD j 0) (inputs.getD (block*8+j) 0)
        else seeded.getD j 0) := by
    conv => lhs; rw [lanes_remap seeded seededShape]
    exact partial_absorption inputs block 8 _ (Nat.le_refl 8)
  unfold poseidon2V8AbsorbBlock
  change Poseidon2Width16Kernel.permutation
    (if block+1 = total then
      ((List.range 8).foldl (absorbStep inputs block) seeded).set 11
        (Poseidon2Width16Kernel.fieldAdd
          (((List.range 8).foldl (absorbStep inputs block) seeded).getD 11 0) 1)
      else (List.range 8).foldl (absorbStep inputs block) seeded) = _
  rw [absorbed]
  apply congrArg Poseidon2Width16Kernel.permutation
  by_cases last : block+1 = total
  · rw [if_pos last, lanes_getD _ 11 (by omega), lanes_set _ 11 _ (by omega)]
    apply congrArg lanes
    funext j
    by_cases marker : j = 11
    · subst j; simp [seeded, last]
    · simp [seeded, last, marker]
  · rw [if_neg last]
    simp [genericFrame, seeded, last]

/-- The source countdown is exactly the increasing block fold, with the last
marker determined by the fixed total first+count. No permutation theorem needed. -/
theorem runBlocks_range_fold (message : Nat → Nat) (length first count : Nat)
    (state : List Nat) :
    runBlocks message length first count state =
      (List.range' first count).foldl
        (fun values block => runBlock message length block
          (decide (block+1 = first+count)) values) state := by
  induction count generalizing first state with
  | zero => simp [runBlocks]
  | succ count ih =>
    rw [runBlocks, List.range'_succ, List.foldl_cons]
    have firstMarker : (first+1 = first+(count+1)) = (count = 0) := by
      apply propext; omega
    have total : (first+1)+count = first+(count+1) := by omega
    simp only [firstMarker]
    rw [ih]
    simp only [total]
end HegemonCrypto.NativePrivateSpendGenericSpongeAbsorption
