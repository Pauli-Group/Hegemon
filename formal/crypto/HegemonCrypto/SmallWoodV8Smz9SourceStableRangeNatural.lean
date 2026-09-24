import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeBounds
import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeTopBits

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableRangeNatural
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeBounds
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeTopBits
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (radixFourSum)
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packedWord)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem source_range_slot_extent (slot : Fin 66) :
    sourceRangeStart slot.val+sourceRangeWidth slot.val/2≤1434 := by
  fin_cases slot <;> decide

theorem full_candidate_range_digit_at (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 66) (digit : Nat) (bound : digit<sourceRangeWidth slot.val/2) :
    (fullTypedSourceCandidate statement witness).getD (42432+sourceRangeStart slot.val+digit) 0 =
      sourceRadixDigit (sourceRangeEntry statement witness slot.val).1 digit := by
  have extent := source_range_slot_extent slot
  have physical := full_candidate_range_digit statement witness (sourceRangeStart slot.val+digit) (by omega)
  have address : 42432+(sourceRangeStart slot.val+digit)=42432+sourceRangeStart slot.val+digit := by omega
  rw [address,source_range_digit_readback statement witness slot digit bound] at physical
  exact physical

theorem full_candidate_range_radix_sum (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 66) (count : Nat) (bound : count≤sourceRangeWidth slot.val/2) :
    radixFourSum (fun digit => (fullTypedSourceCandidate statement witness).getD
        (42432+sourceRangeStart slot.val+digit) 0) count =
      radixFourSum (sourceRadixDigit (sourceRangeEntry statement witness slot.val).1) count := by
  unfold radixFourSum
  congr 1
  apply List.map_congr_left
  intro digit member
  have small : digit<sourceRangeWidth slot.val/2 := lt_of_lt_of_le (List.mem_range.mp member) bound
  dsimp only
  rw [full_candidate_range_digit_at statement witness slot digit small]

theorem full_candidate_even_natural (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 46) :
    stableEvenNatural (fullTypedSourceCandidate statement witness) (sourceEvenSpec index) =
      (sourceRangeEntry statement witness (sourceEvenSpec index).localIndex).1 := by
  have properties := source_even_spec_properties index
  let slot : Fin 66 := ⟨(sourceEvenSpec index).localIndex,properties.1⟩
  have width : sourceRangeWidth slot.val=2*(sourceEvenSpec index).digits := properties.2.1
  have start : sourceRangeStart slot.val=(sourceEvenSpec index).start := properties.2.2.1
  have digitSum := full_candidate_range_radix_sum statement witness slot (sourceEvenSpec index).digits (by rw [width]; omega)
  rw [start] at digitSum
  change stableEvenNatural _ _ = _ at digitSum
  rw [digitSum]
  have bound := source_range_entry_bound statement witness valid slot
  rw [width] at bound
  exact source_radix_even_reconstruct _ _ bound

theorem full_candidate_odd_natural (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 20) :
    stableOddNatural (fullTypedSourceCandidate statement witness) (sourceOddSpec index) =
      (sourceRangeEntry statement witness (sourceOddSpec index).localIndex).1 := by
  have properties := source_odd_spec_properties index
  let slot : Fin 66 := ⟨(sourceOddSpec index).localIndex,by rw [properties.1]; omega⟩
  have width : sourceRangeWidth slot.val=2*(sourceOddSpec index).digits+1 := properties.2.1
  have start : sourceRangeStart slot.val=(sourceOddSpec index).start := properties.2.2.1
  have digitSum := full_candidate_range_radix_sum statement witness slot (sourceOddSpec index).digits (by rw [width]; omega)
  rw [start] at digitSum
  have topAddress : 42112+(sourceOddSpec index).topLane=42145+index.val := by rw [properties.2.2.2.1]; omega
  have topIndex : (sourceRangeEntry statement witness slot.val).2-1=2*(sourceOddSpec index).digits := by
    rw [source_range_entry_width statement witness slot,width]; omega
  have top := full_candidate_odd_top_boolean_readback statement witness index
  rw [← properties.1] at top
  change (fullTypedSourceCandidate statement witness).getD (42145+index.val) 0 =
    sourceBit (sourceRangeEntry statement witness slot.val).1 ((sourceRangeEntry statement witness slot.val).2-1) at top
  rw [topIndex] at top
  unfold stableOddNatural
  simp only [packedWord]
  rw [digitSum,topAddress,top]
  have bound := source_range_entry_bound statement witness valid slot
  rw [width] at bound
  exact source_radix_odd_reconstruct _ _ bound

end HegemonCrypto.SmallWood.V8Smz9SourceStableRangeNatural
