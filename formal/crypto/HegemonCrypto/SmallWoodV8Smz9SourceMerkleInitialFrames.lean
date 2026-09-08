import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies
import Mathlib.Data.Fintype.Fin
import Mathlib.Tactic.FinCases

/-! The actual typed schedule supplies the 64 Merkle compression frames.
The readbacks use the same computed schedule for initial frames and preceding
final words, including level zero and inactive input slots. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceConstructedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceInlineRows
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 1200000

theorem merkle_call_live (step : Fin 64) : V8Smz9InputMerkleSources.merkleCall step.val < 125 := by
  unfold V8Smz9InputMerkleSources.merkleCall inputMerkleCall
  split <;> omega

/-- All 64 source call selectors, not an assumed frame descriptor. -/
theorem actual_merkle_plan (statement : V8PublicStatement) (witness : V8Witness)
    (earlier : Nat → State) (step : Fin 64) :
    sourceCallPlan statement witness (V8Smz9InputMerkleSources.merkleCall step.val) earlier =
      let operands := orient (inputAt witness (step.val/32)).position (step.val%32)
        (finalDigest earlier (previousCall (step.val/32) (step.val%32)))
        (fixedWords 7 ((inputAt witness (step.val/32)).siblings.getD (step.val%32) []))
      Plan.compress (.inputMerkle (step.val/32) (step.val%32)) 4 operands.1 operands.2 := by
  fin_cases step <;> rfl

theorem compress_frame_word (domain : Nat) (left right : List Nat) (lane : Fin 16) :
    (compressFrameWords domain left right).getD lane.val 0 =
      if lane.val < 7 then left.getD lane.val 0
      else if lane.val < 14 then right.getD (lane.val-7) 0
      else if lane.val = 14 then domain else poseidon2V8SuiteMarker := by
  simp only [compressFrameWords, List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range, lane.isLt, Option.map_some, Option.getD_some]

theorem typed_computed_final_word (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (limb : Nat) :
    callFinalWord (typedLiveInitialStates statement witness) call.val limb =
      (stateWords (scheduledFinal statement witness call.val)).getD limb 0 := by
  rw [call_final_word_is_permutation, every_call_has_actual_kernel_final,
    typed_call_initial_exact]

theorem scheduled_digest_word (statement : V8PublicStatement) (witness : V8Witness)
    (call : Fin 125) (limb : Fin 7) :
    (finalDigest (scheduledFinal statement witness) call.val).getD limb.val 0 =
      callFinalWord (typedLiveInitialStates statement witness) call.val limb.val := by
  rw [typed_computed_final_word]
  simp only [finalDigest, List.getD_eq_getElem?_getD, List.getElem?_take,
    limb.isLt, if_true]

theorem actual_merkle_frame_rate (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (step : Fin 64) (lane : Fin 14) :
    (actualSourceFrame statement witness ⟨V8Smz9InputMerkleSources.merkleCall step.val, merkle_call_live step⟩).getD lane.val 0 =
      orientedWord (typedLiveInitialStates statement witness) witness
        (step.val/32) (step.val%32) (lane.val%7) (if lane.val<7 then 1 else 2) := by
  have siblingShape := (typed_sibling_exact statement witness valid
    ⟨step.val/32, by omega⟩ ⟨step.val%32, by omega⟩).1
  have previousBound := previous_call_live (step.val/32) (step.val%32) (by omega) (by omega)
  have previousWord := scheduled_digest_word statement witness
    ⟨previousCall (step.val/32) (step.val%32), previousBound⟩ ⟨lane.val%7, by omega⟩
  rw [actualSourceFrame, actual_merkle_plan]
  dsimp only [rawPreparedPlan]
  rw [compress_frame_word 4 _ _ ⟨lane.val, by omega⟩, orient_is_source_bit]
  have fixedSibling : fixedWords 7 ((inputAt witness (step.val/32)).siblings.getD (step.val%32) []) =
      ((inputAt witness (step.val/32)).siblings.getD (step.val%32) []) :=
    fixed_words_exact 7 _ siblingShape
  rw [fixedSibling]
  by_cases left : lane.val < 7
  · have modulo : lane.val%7 = lane.val := Nat.mod_eq_of_lt left
    simp only [modulo] at previousWord
    rw [modulo]
    simp only [if_pos left, orientedWord, direction,
      V8Smz9SourceReplicatedRows.positionBit, inputAt, siblingWord]
    split <;> simp_all
  · have modulo : lane.val%7 = lane.val-7 := by omega
    simp only [modulo] at previousWord
    rw [modulo]
    simp only [if_neg left, lane.isLt, if_true, orientedWord, direction,
      V8Smz9SourceReplicatedRows.positionBit, inputAt, siblingWord]
    split <;> simp_all

theorem actual_merkle_frame_capacity (statement : V8PublicStatement) (witness : V8Witness)
    (step : Fin 64) (lane : Fin 16) (capacity : 14 ≤ lane.val) :
    (actualSourceFrame statement witness ⟨V8Smz9InputMerkleSources.merkleCall step.val, merkle_call_live step⟩).getD lane.val 0 =
      if lane.val=14 then 4 else poseidon2V8SuiteMarker := by
  rw [actualSourceFrame, actual_merkle_plan]
  dsimp only [rawPreparedPlan]
  rw [compress_frame_word]
  simp only [if_neg (show ¬lane.val<7 by omega), if_neg (show ¬lane.val<14 by omega)]

end HegemonCrypto.SmallWood.V8Smz9SourceMerkleInitial
