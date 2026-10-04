import HegemonCrypto.SmallWoodV8Smz9HashSourceTrace
import HegemonCrypto.SmallWoodV8Smz9HonestHashPlacement

/-! Forward satisfaction of the actual generated HGV8RP03 hash-root span.
The initial live states remain explicit component inputs. No accepted witness,
evaluator success, claimed root equation, or claimed trace equality is a premise.
Unrelated packed words and public inputs are arbitrary and untouched.
-/

namespace HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
open Hegemon.Transaction
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks
open HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
set_option Elab.async false
set_option maxHeartbeats 600000
set_option maxRecDepth 10000
noncomputable section

theorem replay_matches_column (live : LiveInitialStates) (call group : Nat)
    (hg : group < 2) (offset : Nat) (ho : offset < 182) :
    replayRows group (fun i => ((callInitial live call).getD i 0 : F))
        (283 + 182 * group + offset) = ((callColumn live call).getD offset 0 : F) := by
  let initial := fun i => ((callInitial live call).getD i 0 : F)
  let rows := replayRows group initial
  have recurrence : HashRecurrence group (fun _ => 0) rows :=
    replay_has_actual_recurrence group hg initial (fun _ => 0)
  have matched : StateMatches (fun i => rows (283+182*group+i)) (callInitial live call) :=
    ⟨fun i hi => replay_initial group initial i hi⟩
  by_cases start : offset < 16
  · rw [replay_initial group _ offset start, call_column_initial live call offset start]
  · by_cases wire : offset < 166
    · have split : offset = 16 + (offset - 16) := by omega
      have row : 283 + 182 * group + offset = hashRow group (offset - 16) := by
        unfold hashRow
        omega
      have result := recurrence_all_wires (fun _ => 0) rows group hg recurrence
        (callInitial live call) matched (offset-16) (by omega)
      rw [row, split, call_column_wire live call (offset-16) (by omega)]
      simpa only [Nat.add_sub_cancel_left] using result
    · have split : offset = 166 + (offset - 166) := by omega
      have row : 283 + 182 * group + offset = 449 + 182 * group + (offset - 166) := by omega
      have result := hash_recurrence_refines_kernel (fun _ => 0) rows hg recurrence
        (callInitial live call) matched ⟨offset-166, by omega⟩
      rw [row, split, call_column_final, Poseidon2Width16Kernel.compressed_trace_final_state]
      simpa only [Nat.add_sub_cancel_left] using result

theorem placed_lane_is_column (leading suffix : List Nat) (live : LiveInitialStates)
    (leadingLength : leading.length = 18112) (group lane offset : Nat)
    (hg : group < 2) (hl : lane < 64) (ho : offset < 182) :
    laneField (placeHashBlock leading live suffix) lane (283 + 182 * group + offset) =
      ((callColumn live (group * 64 + lane)).getD offset 0 : F) := by
  rw [laneField_eq_packedWord _ _ _ (by omega)]
  have coordinate : (283 + 182 * group + offset) * 64 + lane =
      18112 + ((group * 182 + offset) * 64 + lane) := by omega
  change ((placeHashBlock leading live suffix).getD
    ((283 + 182 * group + offset) * 64 + lane) 0 : F) = _
  rw [coordinate, placed_hash_word leading suffix live leadingLength _ lane (by omega) hl,
    hash_word_at live _ lane (by omega) hl]
  have quotient : (group * 182 + offset) / 182 = group := by omega
  have remainder : (group * 182 + offset) % 182 = offset := by omega
  rw [quotient, remainder]

/-- The concrete constructed block satisfies every exact source recurrence. -/
theorem computed_block_actual_recurrence (leading suffix : List Nat) (live : LiveInitialStates)
    (leadingLength : leading.length = 18112) (pub : Nat → F) (group lane : Nat)
    (hg : group < 2) (hl : lane < 64) :
    HashRecurrence group pub (laneField (placeHashBlock leading live suffix) lane) := by
  let rows := laneField (placeHashBlock leading live suffix) lane
  let initial := fun i => ((callInitial live (group*64+lane)).getD i 0 : F)
  let replay := replayRows group initial
  have recurrence := replay_has_actual_recurrence group hg initial pub
  change HashRecurrence group pub replay at recurrence
  have agree : ∀ offset, offset < 182 →
      rows (283 + 182 * group + offset) = replay (283 + 182 * group + offset) := by
    intro offset ho
    exact (placed_lane_is_column leading suffix live leadingLength group lane offset hg hl ho).trans
      (replay_matches_column live (group*64+lane) group hg offset ho).symm
  intro wire hw
  have row : hashRow group wire = 283 + 182 * group + (16 + wire) := by
    unfold hashRow
    omega
  change rows (hashRow group wire) = fieldAt exactNonlinearExpressions pub rows _
  rw [row, agree (16+wire) (by omega), ← row, recurrence wire hw]
  obtain ⟨_, _, _, lower, upper⟩ := exact_hash_roots_valid hg hw
  apply fieldAt_congr_on_span pub pub replay rows (283 + 182 * group)
    (hashRow group wire) (by unfold hashRow; omega) _ _ lower upper
  intro r lo hi
  have offset : r - (283 + 182 * group) < 182 := by unfold hashRow at hi; omega
  have index : 283 + 182 * group + (r - (283 + 182 * group)) = r := by omega
  have result := (agree (r-(283+182*group)) offset).symm
  simpa only [index] using result

/-- All 2 x 166 named hash roots evaluate to zero, independently in all 64 lanes. -/
theorem computed_block_actual_hash_roots_zero (leading suffix : List Nat) (live : LiveInitialStates)
    (leadingLength : leading.length = 18112) (pub : Nat → F)
    (group lane wire : Nat) (hg : group < 2) (hl : lane < 64) (hw : wire < 166) :
    fieldAt exactNonlinearExpressions pub (laneField (placeHashBlock leading live suffix) lane)
      (hashRootPair group wire).1 = 0 :=
  recurrence_root_zero group hg pub _
    (computed_block_actual_recurrence leading suffix live leadingLength pub group lane hg hl) wire hw

/-- Exact generated-root-list formulation: roots 471 through 802, no surrogate root family. -/
theorem computed_block_exact_root_span_zero (leading suffix : List Nat) (live : LiveInitialStates)
    (leadingLength : leading.length = 18112) (publicWords : List Nat) (lane : Nat) (hl : lane < 64)
    (root : Nat) (member : root ∈ (exactNonlinearRoots.drop 471).take 332) :
    fieldAt exactNonlinearExpressions (fun i => (publicWords.getD i 0 : F))
      (laneField (placeHashBlock leading live suffix) lane) root = 0 := by
  rw [← exact_hash_root_pair_inventory.2] at member
  obtain ⟨pair, pairMember, rootEq⟩ := List.mem_map.mp member
  obtain ⟨index, indexBound, pairEq⟩ := List.getElem_of_mem pairMember
  have size : index < 332 := by simpa only [exact_hash_root_pair_inventory.1] using indexBound
  have pairGet : hashRootPairs.getD index (0,0) = pair := by
    rw [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem indexBound, pairEq]
    rfl
  have indexSplit : 166 * (index / 166) + index % 166 = index := by omega
  have sourcePair : hashRootPair (index/166) (index%166) = pair := by
    simp only [hashRootPair, indexSplit, pairGet]
  have result := computed_block_actual_hash_roots_zero leading suffix live leadingLength
    (fun i => (publicWords.getD i 0 : F)) (index/166) lane (index%166) (by omega) hl (by omega)
  simpa only [sourcePair, rootEq] using result

end
end HegemonCrypto.SmallWood.V8Smz9ForwardHashRoots
