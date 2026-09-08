import HegemonCrypto.SmallWoodV8Smz9SourceAuthLastCore
import HegemonCrypto.SmallWoodV8Smz9SourceRoleAlgebra

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverse
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldSub fieldInverse)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SourceAuthLastCore
open HegemonCrypto.SmallWood.V8Smz9SourceRoleAlgebra
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical (source_sub_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem pair_bounds (pair : Fin 15) :
    (authPairs.getD pair.val (0,0)).1 < (authPairs.getD pair.val (0,0)).2 ∧
      (authPairs.getD pair.val (0,0)).2 < 6 := by
  fin_cases pair <;> decide

theorem active_implies_below (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) (slot : Fin 6)
    (active : authSlotActive witness.authorization slot.val = 1) :
    slot.val < witness.authorization.current.signerCount := by
  rw [slot_active_exact statement witness valid nonsingle slot] at active
  unfold authBit at active
  split_ifs at active with below
  · exact below

theorem selected_pair_inverse (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) (pair : Fin 15)
    (leftActive : authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).1 = 1)
    (rightActive : authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).2 = 1) :
    (authDistinctInverse witness.authorization pair.val : F) *
      ((wordAt (witness.authorization.policySignerTags.getD
          (authPairs.getD pair.val (0,0)).1 []) 0 : F) -
       (wordAt (witness.authorization.policySignerTags.getD
          (authPairs.getD pair.val (0,0)).2 []) 0 : F)) = 1 := by
  have bounds := pair_bounds pair
  have leftBound := lt_trans bounds.1 bounds.2
  have tags := non_single_tags_canonical statement witness valid nonsingle
  have rightBelow := active_implies_below statement witness valid nonsingle
    ⟨_,bounds.2⟩ rightActive
  have different := tags.2.2.2.1 _ _ bounds.1 rightBelow
  have leftCanonical := canonical_signer_tags_source_canonical _ tags (authPairs.getD pair.val (0,0)).1 leftBound 0
  have rightCanonical := canonical_signer_tags_source_canonical _ tags _ bounds.2 0
  have unequal :
      (wordAt (witness.authorization.policySignerTags.getD
          (authPairs.getD pair.val (0,0)).1 []) 0 : F) -
       (wordAt (witness.authorization.policySignerTags.getD
          (authPairs.getD pair.val (0,0)).2 []) 0 : F) ≠ 0 := by
    intro zero
    exact different (canonical_nat_cast_injective leftCanonical rightCanonical (sub_eq_zero.mp zero))
  have selected : witness.authorization.mode ≠ .singleKey ∧
      authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).1 = 1 ∧
      authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).2 = 1 :=
    ⟨nonsingle,leftActive,rightActive⟩
  simp only [authDistinctInverse,if_pos selected]
  have modulus : Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus = fieldModulus := rfl
  rw [canonical_inverse_cast _ (source_sub_canonical _ _),
    field_sub_cast _ _ (by omega)]
  exact inv_mul_cancel₀ unequal

theorem pair_polynomials (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (pair : Fin 15) :
    let a := (authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).1 : F)
    let b := (authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).2 : F)
    let g := (authModeFlag witness.authorization.mode 1 : F) +
      (authModeFlag witness.authorization.mode 2 : F)
    let inv := (authDistinctInverse witness.authorization pair.val : F)
    let diff := (wordAt (witness.authorization.policySignerTags.getD
          (authPairs.getD pair.val (0,0)).1 []) 0 : F) -
       (wordAt (witness.authorization.policySignerTags.getD
          (authPairs.getD pair.val (0,0)).2 []) 0 : F)
    (g*(a*b))*(inv*diff-1) = 0 ∧ inv*(g*(1-a*b)) = 0 := by
  dsimp only
  by_cases single : witness.authorization.mode = .singleKey
  · simp [authModeFlag,authBit,single]
  · have bounds := pair_bounds pair
    have leftBound := lt_trans bounds.1 bounds.2
    have leftBoolean : BooleanWord (authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).1) := by
      rw [slot_active_exact statement witness valid single (⟨(authPairs.getD pair.val (0,0)).1,leftBound⟩ : Fin 6)]
      exact bit_boolean _
    have rightBoolean : BooleanWord (authSlotActive witness.authorization (authPairs.getD pair.val (0,0)).2) := by
      rw [slot_active_exact statement witness valid single ⟨_,bounds.2⟩]
      exact bit_boolean _
    rcases leftBoolean with leftZero | leftOne
    · have invZero : authDistinctInverse witness.authorization pair.val = 0 := by
        simp only [authDistinctInverse,leftZero,Nat.zero_ne_one,false_and,and_false,ite_false]
      simp only [leftZero,invZero,Nat.cast_zero,zero_mul,mul_zero,and_self]
    · rcases rightBoolean with rightZero | rightOne
      · have invZero : authDistinctInverse witness.authorization pair.val = 0 := by
          simp only [authDistinctInverse,rightZero,Nat.zero_ne_one,and_false,ite_false]
        simp only [rightZero,invZero,Nat.cast_zero,zero_mul,mul_zero,and_self]
      · have equation := selected_pair_inverse statement witness valid single pair leftOne rightOne
        rw [equation,leftOne,rightOne]
        norm_num

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthLastInverse
