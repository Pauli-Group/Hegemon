import HegemonCrypto.NativePrivateSpendGenericSpongeAbsorption
import HegemonCrypto.SmallWoodV8Smz9TypedScheduleKernel

/-! Generic pure source/fixed sponge identity. Staged, uncompiled. -/
namespace HegemonCrypto.NativePrivateSpendCurrentSpongeEvaluatorIdentity
open Hegemon.Transaction Hegemon.Transaction.Poseidon2V8SemanticSpecification
open NativePrivateSpendGenericSpongeAbsorption NativePrivateSpendSpongeBridge
open NativePrivateSpendSymbolicBridge NativePrivateSpendLocalSemantics
open NativeLaunchConstraintAdapterBridge
noncomputable section
set_option autoImplicit false
variable [Fact (Nat.Prime modulus)]

def decoded (z : Nat → K) (message : List (Word K)) : List Nat :=
  message.map (fun w => (read z w).val)

theorem decoded_getD (z : Nat → K) (message : List (Word K)) (i : Nat) :
    (decoded z message).getD i 0 = (messageValue z message i).val := by
  induction message generalizing i with
  | nil => simp [decoded, messageValue, NativeLaunchConstraintAdapterBridge.read]
  | cons w ws ih =>
    cases i with
    | zero => simp [decoded, messageValue]
    | succ i => simpa [decoded, messageValue] using ih i

omit [Fact (Nat.Prime modulus)] in
theorem seed_lanes (domain length : Nat) (state : List Nat)
    (shape : state.length = 16) :
    poseidon2V8SeedFirstBlock domain length state =
      lanes (fun i => if i = 8 then domain else if i = 9 then length
        else if i = 10 then poseidon2V8SpongeModeMarker
        else if i = 15 then poseidon2V8SuiteMarker else state.getD i 0) := by
  unfold poseidon2V8SeedFirstBlock
  change (((state.set 8 domain).set 9 length).set 10 poseidon2V8SpongeModeMarker).set
    15 poseidon2V8SuiteMarker = _
  conv => lhs; rw [lanes_remap state shape]
  rw [lanes_set _ 8 _ (by omega), lanes_set _ 9 _ (by omega),
    lanes_set _ 10 _ (by omega), lanes_set _ 15 _ (by omega)]
  apply List.map_congr_left
  intro i hi
  split_ifs <;> simp_all

theorem source_seed_exact (z : Nat → K) (domain : K) (length : Nat)
    (canonicalLength : length < modulus) :
    stateNaturals z (spongeFrame domain length) =
      poseidon2V8SeedFirstBlock domain.val length poseidon2V8InitialState := by
  rw [seed_lanes _ _ _ (by simp [poseidon2V8InitialState, Poseidon2Width16Kernel.width])]
  change (List.range 16).map _ = (List.range 16).map _
  apply List.map_congr_left
  intro i hi
  have bound : i < 16 := List.mem_range.mp hi
  have lengthVal : (length : K).val = length := ZMod.val_natCast_of_lt canonicalLength
  have modeVal : (0x53504f4e47455631 : K).val = 0x53504f4e47455631 := by
    exact ZMod.val_ofNat_of_lt (by decide : 0x53504f4e47455631 < modulus)
  have suiteVal : (0x4845475f50323136 : K).val = 0x4845475f50323136 := by
    exact ZMod.val_ofNat_of_lt (by decide : 0x4845475f50323136 < modulus)
  have zeroLane : poseidon2V8InitialState.getD i 0 = 0 := by
    simp only [poseidon2V8InitialState, Poseidon2Width16Kernel.width,
      List.getD_eq_getElem?_getD, List.getElem?_replicate_of_lt bound, Option.getD_some]
  simp only [stateValue, words, dif_pos bound, spongeFrame,
    NativeLaunchConstraintAdapterBridge.read]
  dsimp only [poseidon2V8SpongeModeMarker, poseidon2V8SuiteMarker]
  split_ifs <;> simp_all

omit [Fact (Nat.Prime modulus)] in
/-- Every common permutation result has exactly sixteen words. -/
theorem permutation_shape (state : List Nat) :
    (Poseidon2Width16Kernel.permutation state).length = 16 := by
  have shape := SmallWood.V8Smz9HonestHashMaterialization.compressed_trace_final_length state
  change (Poseidon2Width16Kernel.compressedTrace state).finalState.length = 16 at shape
  rwa [Poseidon2Width16Kernel.compressed_trace_final_state] at shape

omit [Fact (Nat.Prime modulus)] in
theorem later_frame (domain : Nat) (inputs state : List Nat) (total block : Nat)
    (positive : 0 < block) :
    genericFrame domain inputs state total block =
      absorbNaturals (fun i => inputs.getD i 0) inputs.length block
        (decide (block+1 = total)) state := by
  have nonzero : block ≠ 0 := by omega
  simp [genericFrame, absorbNaturals, lanes, nonzero, Nat.mul_comm]

omit [Fact (Nat.Prime modulus)] in
theorem first_frame (domain : Nat) (inputs : List Nat) (total : Nat) :
    genericFrame domain inputs poseidon2V8InitialState total 0 =
      absorbNaturals (fun i => inputs.getD i 0) inputs.length 0
        (decide (1 = total))
        (poseidon2V8SeedFirstBlock domain inputs.length poseidon2V8InitialState) := by
  simp [genericFrame, absorbNaturals, lanes]

omit [Fact (Nat.Prime modulus)] in
theorem later_blocks (domain : Nat) (inputs : List Nat) (first count : Nat)
    (state : List Nat) (positive : 0 < first) (shape : state.length = 16) :
    runBlocks (fun i => inputs.getD i 0) inputs.length first count state =
      (List.range' first count).foldl
        (poseidon2V8AbsorbBlock domain inputs (first+count)) state := by
  induction count generalizing first state with
  | zero => simp [runBlocks]
  | succ count ih =>
    rw [runBlocks, List.range'_succ, List.foldl_cons]
    have marker : (first+1 = first+(count+1)) = (count = 0) := by
      apply propext; omega
    have step : runBlock (fun i => inputs.getD i 0) inputs.length first
        (decide (count = 0)) state =
        poseidon2V8AbsorbBlock domain inputs (first+(count+1)) state first := by
      rw [generic_absorb_frame _ _ _ _ _ shape, later_frame _ _ _ _ _ positive]
      simp only [runBlock, marker]
    rw [step]
    have nextShape :
        (poseidon2V8AbsorbBlock domain inputs (first+(count+1)) state first).length = 16 := by
      rw [generic_absorb_frame _ _ _ _ _ shape]
      exact permutation_shape _
    have total : (first+1)+count = first+(count+1) := by omega
    simpa only [total] using ih (first+1) _ (by omega) nextShape

/-- Exact source readout equals the fixed evaluator on the same canonical
message words, including arbitrary short final blocks and the empty message. -/
theorem sponge_evaluator_exact (z : Nat → K) (domain : K)
    (message : List (Word K)) (canonicalLength : message.length < modulus) :
    (spongeNaturals z domain message).take 7 =
      poseidon2V8Sponge domain.val (message.map (fun w => (read z w).val)) := by
  let inputs := decoded z message
  have lengthEq : inputs.length = message.length := by simp [inputs, decoded]
  have wordsEq : (fun i => (messageValue z message i).val) =
      (fun i => inputs.getD i 0) := by
    funext i
    exact (decoded_getD z message i).symm
  have blocksPositive : 1 ≤ blockCount message.length := by
    exact Nat.le_max_left _ _
  cases countEq : blockCount message.length with
  | zero => omega
  | succ count =>
    have firstStep :
        runBlock (fun i => inputs.getD i 0) message.length 0 (decide (count=0))
          (stateNaturals z (spongeFrame domain message.length)) =
        poseidon2V8AbsorbBlock domain.val inputs (count+1) poseidon2V8InitialState 0 := by
      rw [source_seed_exact z domain message.length canonicalLength]
      rw [generic_absorb_frame _ _ _ _ _
        (by simp [poseidon2V8InitialState, Poseidon2Width16Kernel.width]), first_frame]
      have marker : (1 = count+1) = (count = 0) := by apply propext; omega
      simp only [marker, lengthEq, runBlock]
    have firstShape :
        (poseidon2V8AbsorbBlock domain.val inputs (count+1) poseidon2V8InitialState 0).length = 16 := by
      rw [generic_absorb_frame _ _ _ _ _
        (by simp [poseidon2V8InitialState, Poseidon2Width16Kernel.width])]
      exact permutation_shape _
    have tail := later_blocks domain.val inputs 1 count _ (by omega) firstShape
    have blockEq :
        Nat.max 1 ((inputs.length+Poseidon2Width16Kernel.rate-1) /
          Poseidon2Width16Kernel.rate) = count+1 := by
      change Nat.max 1 ((inputs.length+8-1)/8) = count+1
      have numerator : inputs.length+8-1 = inputs.length+7 := by omega
      rw [numerator, lengthEq]
      exact countEq
    change _ = poseidon2V8Sponge domain.val inputs
    unfold spongeNaturals
    rw [wordsEq, countEq, runBlocks, firstStep]
    unfold poseidon2V8Sponge
    rw [blockEq]
    dsimp only [digestWords]
    rw [List.range_eq_range', List.range'_succ, List.foldl_cons]
    rw [← lengthEq]
    simpa only [Nat.zero_add, Nat.add_comm] using congrArg (fun xs : List Nat => xs.take 7) tail
end
end HegemonCrypto.NativePrivateSpendCurrentSpongeEvaluatorIdentity
