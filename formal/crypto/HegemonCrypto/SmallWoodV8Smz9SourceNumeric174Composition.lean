import HegemonCrypto.SmallWoodV8Smz9SourceNonmint40
import HegemonCrypto.SmallWoodV8Smz9SourceNonmintCsr40
import HegemonCrypto.SmallWoodV8Smz9SourceStableDecimalEpoch22
import HegemonCrypto.SmallWoodV8Smz9SourceStableInitial15
import HegemonCrypto.SmallWoodV8Smz9SourceStableRetirement8
import HegemonCrypto.SmallWoodV8Smz9SourceStableRetirement15
import HegemonCrypto.SmallWoodV8Smz9SourceStableCarry18
import HegemonCrypto.SmallWoodV8Smz9SourceStableFinalBorrowCsr
import HegemonCrypto.SmallWoodV8Smz9SourceStableTime15
import HegemonCrypto.SmallWoodV8Smz9SourceStableRetirement4
import HegemonCrypto.SmallWoodV8Smz9SourceStableProduct30
import HegemonCrypto.SmallWoodV8Smz9SourceStableCollateral6

namespace HegemonCrypto.SmallWood.V8Smz9SourceNumeric174Composition

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr (liveTypedPub)
open HegemonCrypto.SmallWood.V8Smz9SourceNonmintCsr40
open HegemonCrypto.SmallWood.V8Smz9SourceStableDecimalEpoch22
open HegemonCrypto.SmallWood.V8Smz9SourceStableInitial15
open HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement8
open HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement15
open HegemonCrypto.SmallWood.V8Smz9SourceStableCarry18
open HegemonCrypto.SmallWood.V8Smz9SourceStableFinalBorrowCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableTime15
open HegemonCrypto.SmallWood.V8Smz9SourceStableRetirement4
open HegemonCrypto.SmallWood.V8Smz9SourceStableProduct30
open HegemonCrypto.SmallWood.V8Smz9SourceStableCollateral6
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr (actualCsrResidual)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated (exactCsrAttempts)

set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

noncomputable section

def actualSourcePub (statement : V8PublicStatement) : Nat → F := liveTypedPub statement

def numeric174Group (i : Nat) : Prop :=
  i < 15 ∨ (15 ≤ i ∧ i < 55) ∨ i = 55 ∨
  (56 ≤ i ∧ i < 71) ∨ (71 ≤ i ∧ i < 78) ∨
  (78 ≤ i ∧ i < 93) ∨ (93 ≤ i ∧ i < 101) ∨
  (101 ≤ i ∧ i < 105) ∨ (105 ≤ i ∧ i < 120) ∨
  (120 ≤ i ∧ i < 122) ∨ (122 ≤ i ∧ i < 152) ∨
  (152 ≤ i ∧ i < 156) ∨ (156 ≤ i ∧ i < 174)

instance (i : Nat) : Decidable (numeric174Group i) := by
  unfold numeric174Group
  infer_instance

theorem numeric174_group_coverage :
    (List.range 174).all (fun i => decide (numeric174Group i)) = true := by
  decide

theorem full_candidate_actual_numeric174_zero
    (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (index : Fin 174) :
    (exactCsrAttempts[20320 + index.val]?).map
      (actualCsrResidual (actualSourcePub statement)
        (fullTypedSourceCandidate statement witness)) = some 0 := by
  have covered : numeric174Group index.val := by
    have all' : ∀ i, i < 174 → numeric174Group i := by
      simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using
        numeric174_group_coverage
    exact all' index.val index.isLt
  rcases covered with initial | nonmint | finalBorrow | decimal | epoch | time |
      retirementGate | retirementTime | retirementBasic | collateralHead |
      product | collateralTail | carry
  · simpa only [actualSourcePub] using
      (full_candidate_actual_initial15_zero statement witness valid
        ⟨index.val, by omega⟩)
  · simpa only [actualSourcePub, show 20335 + (index.val - 15) = 20320 + index.val by omega] using
      (full_candidate_actual_nonmint40_zero statement witness valid
        ⟨index.val - 15, by omega⟩)
  · simpa only [actualSourcePub, show 20375 = 20320 + index.val by omega] using
      (full_candidate_actual_final_borrow_zero statement witness valid)
  · simpa only [actualSourcePub, show 20376 + (index.val - 56) = 20320 + index.val by omega] using
      (full_candidate_actual_decimal15_zero statement witness
        ⟨index.val - 56, by omega⟩)
  · simpa only [actualSourcePub, show 20391 + (index.val - 71) = 20320 + index.val by omega] using
      (full_candidate_actual_epoch7_zero statement witness
        ⟨index.val - 71, by omega⟩)
  · simpa only [actualSourcePub, show 20398 + 3 * ((index.val - 78) / 3) +
      ((index.val - 78) % 3) = 20320 + index.val by omega] using
      (full_candidate_actual_time15_zero statement witness valid
        ⟨(index.val - 78) / 3, by omega⟩ ⟨(index.val - 78) % 3, by omega⟩)
  · simpa only [actualSourcePub, show 20413 + (index.val - 93) = 20320 + index.val by omega] using
      (full_candidate_actual_retirement_gates8_zero statement witness valid
        ⟨index.val - 93, by omega⟩)
  · by_cases high : (index.val - 101) % 2 = 1
    · simpa only [actualSourcePub, if_true, Nat.add_zero,
        show 20421 + 2 * ((index.val - 101) / 2) + 1 = 20320 + index.val by omega] using
        (full_candidate_actual_retirement4_zero statement witness valid
          ⟨(index.val - 101) / 2, by omega⟩ true)
    · simpa only [actualSourcePub, Bool.false_eq_true, if_false, Nat.add_zero,
        show 20421 + 2 * ((index.val - 101) / 2) = 20320 + index.val by omega] using
        (full_candidate_actual_retirement4_zero statement witness valid
          ⟨(index.val - 101) / 2, by omega⟩ false)
  · simpa only [actualSourcePub, show 20425 + (index.val - 105) = 20320 + index.val by omega] using
      (full_candidate_actual_retirement_basic15_zero statement witness valid
        ⟨index.val - 105, by omega⟩)
  · simpa only [actualSourcePub,
      show collateral6Global (index.val - 120) = 20320 + index.val by
        dsimp only [collateral6Global]; split_ifs <;> omega] using
      (full_candidate_actual_collateral6_zero statement witness valid
        ⟨index.val - 120, by omega⟩)
  · simpa only [actualSourcePub,
      show 20442 + 3 * ((index.val - 122) / 3) + ((index.val - 122) % 3) =
        20320 + index.val by omega] using
      (full_candidate_actual_product30_zero statement witness valid
        ⟨(index.val - 122) / 3, by omega⟩ ⟨(index.val - 122) % 3, by omega⟩)
  · simpa only [actualSourcePub,
      show collateral6Global ((index.val - 152) + 2) = 20320 + index.val by
        dsimp only [collateral6Global]; split_ifs <;> omega] using
      (full_candidate_actual_collateral6_zero statement witness valid
        ⟨(index.val - 152) + 2, by omega⟩)
  · simpa only [actualSourcePub,
      show 20476 + (index.val - 156) = 20320 + index.val by omega] using
      (full_candidate_actual_carry18_zero statement witness valid
        ⟨index.val - 156, by omega⟩)

end
end HegemonCrypto.SmallWood.V8Smz9SourceNumeric174Composition
