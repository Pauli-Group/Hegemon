import HegemonCrypto.SmallWoodV8Smz9SourceStableCounterArithmetic
import HegemonCrypto.SmallWoodV8Smz9SourceNonmint40
import HegemonCrypto.SmallWoodV8Smz9SourceStableNumericReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableFinalBorrow
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceStableCounterArithmetic
open HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
open HegemonCrypto.SmallWood.V8Smz9SourceNonmint40
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceStableNumericReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

theorem source_four_limb_recomposition (value : Nat) (bound : value < 2^128) :
    value % limbBase + (value / limbBase) % limbBase * limbBase +
      (value / limbBase^2) % limbBase * limbBase^2 +
      (value / limbBase^3) % limbBase * limbBase^3 = value := by
  have first := Nat.mod_add_div value limbBase
  have second := Nat.mod_add_div (value / limbBase) limbBase
  have third := Nat.mod_add_div (value / limbBase^2) limbBase
  have last := Nat.mod_add_div (value / limbBase^3) limbBase
  norm_num [limbBase,Nat.div_div_eq_div_mul] at first second third last bound ⊢
  omega

theorem source_borrow_four_zero (left right : Nat → Nat)
    (leftBounds : ∀ index : Fin 4, left index.val < limbBase)
    (rightBounds : ∀ index : Fin 4, right index.val < limbBase)
    (ordered : right 0 + right 1 * limbBase + right 2 * limbBase^2 + right 3 * limbBase^3 ≤
      left 0 + left 1 * limbBase + left 2 * limbBase^2 + left 3 * limbBase^3) :
    sourceBorrow left right 4 = 0 := by
  have l0 := leftBounds ⟨0,by decide⟩
  have l1 := leftBounds ⟨1,by decide⟩
  have l2 := leftBounds ⟨2,by decide⟩
  have l3 := leftBounds ⟨3,by decide⟩
  have r0 := rightBounds ⟨0,by decide⟩
  have r1 := rightBounds ⟨1,by decide⟩
  have r2 := rightBounds ⟨2,by decide⟩
  have r3 := rightBounds ⟨3,by decide⟩
  norm_num only [limbBase,Nat.reducePow] at ordered l0 l1 l2 l3 r0 r1 r2 r3
  simp only [sourceBorrow]
  split_ifs <;> omega

theorem source_mul3_four_limb_recomposition (x y z : Nat) (bound : x*y*z < 2^128) :
    let limbs := sourceMul3 x y z
    limbs.out 0 + limbs.out 1 * limbBase + limbs.out 2 * limbBase^2 + limbs.out 3 * limbBase^3 = x*y*z := by
  simpa only [sourceMul3,pow_zero,pow_one,Nat.div_one] using source_four_limb_recomposition (x*y*z) bound

theorem valid_source_final_borrow_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (sourceAux statement.stablecoin witness.stablecoin).collateral.borrows 3 = 0 := by
  by_cases mint : statement.stablecoin.direction = .mint
  · have active : statement.stablecoin.direction ≠ .disabled := by rw [mint]; decide
    have bounds := valid_numeric_input_bounds statement witness valid
    have ordered := valid_source_mint_collateral statement witness valid mint
    have leftBound := (typed_mul3_products_fit_u128 _ _ _ bounds.amount bounds.numerator (by decide : 1000000 < 2^32)).2
    have rightBound := (typed_mul3_products_fit_u128 _ _ _ bounds.debt bounds.denominator bounds.ratio).2
    have left := source_mul3_four_limb_recomposition _ _ _ leftBound
    have right := source_mul3_four_limb_recomposition _ _ _ rightBound
    simp only [sourceAux,if_neg active,if_pos mint,sourceCollateral]
    apply source_borrow_four_zero
    · intro index; exact source_mul3_output_bound _ _ _ _
    · intro index; exact source_mul3_output_bound _ _ _ _
    · rw [left,right]
      exact ordered
  · by_cases disabled : statement.stablecoin.direction = .disabled
    · simp [sourceAux,disabled,disabledSourceAux]
    · simp [sourceAux,disabled,mint]

theorem full_candidate_final_borrow_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    (fullTypedSourceCandidate statement witness).getD 42137 0 = 0 := by
  rw [full_candidate_boolean_absolute statement witness _ (by decide) (by decide)]
  simpa [sourceBooleanValues,List.ofFn_succ] using valid_source_final_borrow_zero statement witness valid

end HegemonCrypto.SmallWood.V8Smz9SourceStableFinalBorrow
