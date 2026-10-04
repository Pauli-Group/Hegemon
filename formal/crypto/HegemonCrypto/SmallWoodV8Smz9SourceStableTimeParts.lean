import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeNatural
import HegemonCrypto.SmallWoodV8Smz9StableLifecycleEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableTimeParts

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeBounds
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeNatural
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeTopBits
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (radixFourSum radix_four_sum_bound)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord)

set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def sourceTimeIndex (i : Fin 14) : Fin 20 :=
  ⟨if i.val < 6 then i.val else if i.val = 6 then 7 else i.val + 3, by split_ifs <;> omega⟩

theorem source_time_spec_eq (i : Fin 14) :
    sourceOddSpec (sourceTimeIndex i) = timeSpec i := by
  fin_cases i <;> rfl

theorem source_time_parts
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (i : Fin 14) :
    (sourceRangeEntry statement witness (timeSpec i).localIndex).1 =
        timeLow (fullTypedSourceCandidate statement witness) (timeSpec i).start +
          2 ^ 32 * timeHigh (fullTypedSourceCandidate statement witness)
            (timeSpec i).start (timeSpec i).topLane ∧
      timeLow (fullTypedSourceCandidate statement witness) (timeSpec i).start < 2 ^ 32 ∧
      timeHigh (fullTypedSourceCandidate statement witness)
          (timeSpec i).start (timeSpec i).topLane < 2 ^ 31 := by
  let slot : Fin 66 := ⟨(timeSpec i).localIndex, by fin_cases i <;> decide⟩
  have slotWidth : sourceRangeWidth slot.val = 63 := by
    fin_cases i <;> decide
  have slotStart : sourceRangeStart slot.val = (timeSpec i).start := by
    fin_cases i <;> decide
  have digitBound (d : Nat) (hd : d < 31) :
      (fullTypedSourceCandidate statement witness).getD
          (42432 + (timeSpec i).start + d) 0 < 4 := by
    have physical := full_candidate_range_digit_at statement witness slot d (by
      rw [slotWidth]
      omega)
    rw [slotStart] at physical
    rw [physical]
    exact source_radix_digit_bound _ _
  have lowBound : timeLow (fullTypedSourceCandidate statement witness)
      (timeSpec i).start < 2 ^ 32 := by
    unfold timeLow
    have h := radix_four_sum_bound
      (fun d => packedWord (fullTypedSourceCandidate statement witness)
        (42432 + (timeSpec i).start + d)) 16 (by
          intro d hd
          exact digitBound d (by omega))
    norm_num only [Nat.reducePow] at h ⊢
    exact h
  have topAddress : 42112 + (timeSpec i).topLane =
      42145 + (sourceTimeIndex i).val := by
    fin_cases i <;> decide
  have topRead := full_candidate_odd_top_boolean_readback statement witness
    (sourceTimeIndex i)
  rw [←topAddress] at topRead
  have topBound : packedWord (fullTypedSourceCandidate statement witness)
      (42112 + (timeSpec i).topLane) ≤ 1 := by
    simp only [packedWord]
    rw [topRead]
    unfold sourceBit
    have small := Nat.mod_lt
      ((sourceRangeEntry statement witness (7+(sourceTimeIndex i).val)).1 /
        2^((sourceRangeEntry statement witness (7+(sourceTimeIndex i).val)).2-1))
      (by decide : 0 < 2)
    omega
  have highLowBound : radixFourSum
      (fun d => packedWord (fullTypedSourceCandidate statement witness)
        (42432 + (timeSpec i).start + 16 + d)) 15 < 4 ^ 15 := by
    apply radix_four_sum_bound
    intro d hd
    simpa only [packedWord,Nat.add_assoc] using digitBound (16 + d) (by omega)
  have highBound : timeHigh (fullTypedSourceCandidate statement witness)
      (timeSpec i).start (timeSpec i).topLane < 2 ^ 31 := by
    unfold timeHigh
    have product := Nat.mul_le_mul_left (4 ^ 15) topBound
    norm_num only [Nat.reducePow] at highLowBound product ⊢
    omega
  have natural := full_candidate_odd_natural statement witness valid (sourceTimeIndex i)
  rw [source_time_spec_eq] at natural
  have decomposition : stableOddNatural (fullTypedSourceCandidate statement witness)
      (timeSpec i) = timeLow (fullTypedSourceCandidate statement witness)
        (timeSpec i).start + 2 ^ 32 * timeHigh
          (fullTypedSourceCandidate statement witness) (timeSpec i).start
          (timeSpec i).topLane := by
    unfold stableOddNatural timeLow timeHigh
    have split := radix_four_sum_split
      (fun d => packedWord (fullTypedSourceCandidate statement witness)
        (42432 + (timeSpec i).start + d)) 16 15
    rw [show (timeSpec i).digits = 31 by fin_cases i <;> rfl]
    rw [show (31 : Nat) = 16 + 15 by decide, split]
    simp only [Nat.add_assoc]
    norm_num only [Nat.reducePow]
    ring
  have valueEq : stableOddNatural (fullTypedSourceCandidate statement witness)
      (timeSpec i) = (sourceRangeEntry statement witness (timeSpec i).localIndex).1 := natural
  exact ⟨valueEq ▸ decomposition, lowBound, highBound⟩

theorem source_time_parts_mod_div
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (i : Fin 14) :
    timeLow (fullTypedSourceCandidate statement witness) (timeSpec i).start =
        (sourceRangeEntry statement witness (timeSpec i).localIndex).1 % 2 ^ 32 ∧
    timeHigh (fullTypedSourceCandidate statement witness)
        (timeSpec i).start (timeSpec i).topLane =
        (sourceRangeEntry statement witness (timeSpec i).localIndex).1 / 2 ^ 32 := by
  rcases source_time_parts statement witness valid i with ⟨h, low, high⟩
  constructor <;> rw [h]
  · omega
  · omega

end HegemonCrypto.SmallWood.V8Smz9SourceStableTimeParts
