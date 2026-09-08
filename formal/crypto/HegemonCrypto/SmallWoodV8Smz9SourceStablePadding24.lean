import HegemonCrypto.SmallWoodV8Smz9SourceStableRangeDigits
import HegemonCrypto.SmallWoodV8Smz9SourceTailNumericCanonical
import HegemonCrypto.SmallWoodV8Smz9SourceDenseCsr
import HegemonCrypto.SmallWoodV8Smz9SourceStableLiveRoleCsr
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceStablePadding24
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableRangeDigits
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr (liveTypedPub)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityGenerated
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrTable (csr_chunks037_member)
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies (exact_attempt_lookup)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def highRangeSlot (group : Nat) : Nat := [39,42,47,51,54,59].getD group 0
def stablePaddingAddress (index : Nat) : Nat := 42432+sourceRangeStart (highRangeSlot (index/4))+12+index%4
def stablePaddingAttempt (index : Nat) : CsrExecutableAttempt :=
  attempt (20296+index) 62 index 0 [(stablePaddingAddress index,1)] 0

theorem high_range_slot_bounds (group : Fin 6) :
    highRangeSlot group.val<66 ∧ sourceRangeWidth (highRangeSlot group.val)=32 := by
  fin_cases group <;> decide

theorem high_range_slot_start_bound (group : Fin 6) :
    sourceRangeStart (highRangeSlot group.val)≤1322 := by
  fin_cases group <;> decide

theorem source_high_limb_bound (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (group : Fin 6) :
    (sourceRangeEntry statement witness (highRangeSlot group.val)).1<2^24 := by
  have numeric := valid_numeric_input_bounds statement witness valid
  have left := actual_left_mul3_bounds statement witness numeric
  have right := actual_right_mul3_bounds statement witness numeric
  fin_cases group <;> first
    | exact left.x1
    | exact left.p2
    | exact left.out3
    | exact right.x1
    | exact right.p2
    | exact right.out3

theorem source_high_radix_digit_zero (value digit : Nat) (bound : value<2^24) (high : 12≤digit) :
    sourceRadixDigit value digit=0 := by
  have power : (2:Nat)^24≤2^(2*digit) := Nat.pow_le_pow_right (by decide) (by omega)
  simp only [sourceRadixDigit,Nat.div_eq_of_lt (lt_of_lt_of_le bound power),Nat.zero_mod]

theorem full_candidate_high_padding_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 24) :
    (fullTypedSourceCandidate statement witness).getD (stablePaddingAddress index.val) 0=0 := by
  let group : Fin 6 := ⟨index.val/4,by omega⟩
  have properties := high_range_slot_bounds group
  let slot : Fin 66 := ⟨highRangeSlot group.val,properties.1⟩
  have digitBound : 12+index.val%4<sourceRangeWidth slot.val/2 := by
    change 12+index.val%4<sourceRangeWidth (highRangeSlot group.val)/2
    rw [properties.2]; omega
  have addressBound : sourceRangeStart slot.val+(12+index.val%4)<1472 := by
    have start := high_range_slot_start_bound group
    change sourceRangeStart (highRangeSlot group.val)+(12+index.val%4)<1472
    omega
  have digitReadback := source_range_digit_readback statement witness slot (12+index.val%4) digitBound
  have physical := full_candidate_range_digit statement witness _ addressBound
  have address : 42432+(sourceRangeStart slot.val+(12+index.val%4))=stablePaddingAddress index.val := by
    simp only [stablePaddingAddress,slot,group]; omega
  rw [address,digitReadback] at physical
  rw [physical]
  exact source_high_radix_digit_zero _ _ (source_high_limb_bound statement witness valid group) (by omega)

theorem stable_padding_chunk_member (index : Fin 24) :
    stablePaddingAttempt index.val ∈ V8Smz9ProgramCanonicalityCsr39.chunk010 := by
  fin_cases index <;> decide

theorem stable_padding_chunk_in_complete : V8Smz9ProgramCanonicalityCsr39.chunk010 ∈ csrChunks000 := by
  have member : V8Smz9ProgramCanonicalityCsr39.chunk010 ∈ V8Smz9ProgramCanonicalityCsr39.chunkList := by
    simp only [V8Smz9ProgramCanonicalityCsr39.chunkList,List.mem_cons,List.not_mem_nil,or_false]
    exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl True.intro))))))))))
  exact csr_chunks037_member _ (List.mem_append_right _ (List.mem_append_right _ (List.mem_append_left _ member)))

theorem stable_padding_exact_lookup (index : Fin 24) :
    exactCsrAttempts[20296+index.val]?=some (stablePaddingAttempt index.val) := by
  apply exact_attempt_lookup (stablePaddingAttempt index.val)
  rw [←csr_chunks_equal_materialized_attempts]
  exact List.mem_flatten.mpr ⟨_,stable_padding_chunk_in_complete,stable_padding_chunk_member index⟩

noncomputable section
theorem full_candidate_actual_padding24_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 24) :
    (exactCsrAttempts[20296+index.val]?).map
      (actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness))=some 0 := by
  rw [stable_padding_exact_lookup]
  simp only [Option.map_some,actualCsrResidual,stablePaddingAttempt,attempt,actualCsrTerms,
    List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,(actual_csr_zero_one _).1,
    (actual_csr_zero_one _).2,full_candidate_high_padding_zero statement witness valid index,
    Nat.cast_zero,mul_zero,add_zero,sub_zero]
end
end HegemonCrypto.SmallWood.V8Smz9SourceStablePadding24
