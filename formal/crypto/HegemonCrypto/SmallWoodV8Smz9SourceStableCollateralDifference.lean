import HegemonCrypto.SmallWoodV8Smz9SourceStableFinalBorrow

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableCollateralDifference
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem source_borrow_bound (left right : Nat → Nat) (index : Nat) :
    sourceBorrow left right index ≤ 1 := by
  cases index with
  | zero => change 0 ≤ 1; decide
  | succ index => simp only [sourceBorrow]; split_ifs <;> omega

theorem source_difference_recomposition (left right : Nat → Nat) (index : Nat)
    (rightBound : right index < limbBase) :
    left index + limbBase * sourceBorrow left right (index+1) =
      right index + sourceBorrow left right index + sourceDifference left right index := by
  have borrow := source_borrow_bound left right index
  simp only [sourceDifference,sourceBorrow]
  split_ifs <;> omega

theorem actual_difference_recomposition (statement : V8PublicStatement) (witness : V8Witness)
    (index : Nat) :
    let aux := (sourceAux statement.stablecoin witness.stablecoin).collateral
    aux.left.out index + limbBase * aux.borrows index = aux.right.out index +
      (if index = 0 then 0 else aux.borrows (index-1)) + aux.difference index := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · simp [sourceAux,disabled,disabledSourceAux]
  · by_cases mint : statement.stablecoin.direction = .mint
    · simp only [sourceAux,if_neg disabled,if_pos mint,sourceCollateral]
      have previous (left right : Nat → Nat) :
          (if index = 0 then 0 else sourceBorrow left right (index-1+1)) = sourceBorrow left right index := by
        cases index <;> simp [sourceBorrow]
      rw [previous]
      exact source_difference_recomposition _ _ _ (source_mul3_output_bound _ _ _ _)
    · simp [sourceAux,disabled,mint]

noncomputable section
theorem actual_difference_field (statement : V8PublicStatement) (witness : V8Witness) (index : Nat) :
    let aux := (sourceAux statement.stablecoin witness.stablecoin).collateral
    (aux.left.out index : F) - (aux.right.out index : F) -
      ((if index = 0 then 0 else aux.borrows (index-1) : Nat) : F) +
      4294967296 * (aux.borrows index : F) - (aux.difference index : F) = 0 := by
  have equation := congrArg (fun value : Nat => (value : F)) (actual_difference_recomposition statement witness index)
  simp only [Nat.cast_add,Nat.cast_mul,limbBase,Nat.cast_pow,Nat.cast_ofNat] at equation
  dsimp only
  linear_combination equation
end
end HegemonCrypto.SmallWood.V8Smz9SourceStableCollateralDifference
