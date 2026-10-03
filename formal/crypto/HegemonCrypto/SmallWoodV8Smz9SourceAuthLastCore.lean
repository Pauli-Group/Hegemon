import HegemonCrypto.SmallWoodV8Smz9SourceAuthRemainingCore
import HegemonCrypto.SmallWoodV8Smz9SourceAuthMoreClosure

namespace HegemonCrypto.SmallWood.V8Smz9SourceAuthLastCore
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRemainingCore
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false
noncomputable section

theorem non_single_tags_canonical (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) :
    CanonicalSignerTags witness.authorization := by
  have auth := valid.2.2.1.2.2
  cases mode : witness.authorization.mode
  · exact False.elim (nonsingle mode)
  · simp only [V8AuthorizationValid,mode] at auth
    exact auth.2.2.2.2.1
  · simp only [V8AuthorizationValid,mode] at auth
    exact auth.2.2.2.1

theorem approval_signer_count (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (approval : witness.authorization.mode = .approvalStep) :
    witness.authorization.next.signerCount = witness.authorization.current.signerCount := by
  have auth := valid.2.2.1.2.2
  simp only [V8AuthorizationValid,approval] at auth
  exact auth.2.2.2.2.2.2.2.2.2.1

theorem slot_active_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) (slot : Fin 6) :
    authSlotActive witness.authorization slot.val =
      authBit (slot.val < witness.authorization.current.signerCount) := by
  obtain ⟨positive,threshold,upper,_⟩ := current_scalar_bounds statement witness valid nonsingle
  have lower : 1 ≤ witness.authorization.current.signerCount := by omega
  simp only [authSlotActive,authSignerFlag,if_neg nonsingle]
  interval_cases witness.authorization.current.signerCount <;>
    fin_cases slot <;> norm_num [authBit,List.range_succ]

theorem selected_slot_active (auth : V8AuthorizationWitness) (hashes : AuthHashFinals)
    (slot : Nat) :
    (1-(authSlotActive auth slot : F)) * (authMembership auth hashes slot : F) = 0 := by
  unfold authMembership authBit
  split_ifs with selected
  · simp [selected.2.1]
  · simp

theorem inactive_bitmap (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (next : Bool) (slot : Fin 6) :
    (wordAt (if next then witness.authorization.next.approvedSlots
      else witness.authorization.current.approvedSlots) slot.val : F) *
      ((authModeFlag witness.authorization.mode (if next then 1 else 1) : F) +
        (if next then 0 else (authModeFlag witness.authorization.mode 2 : F))) *
      (1-(authSlotActive witness.authorization slot.val : F)) = 0 := by
  cases mode : witness.authorization.mode
  · cases next <;> simp [authModeFlag,authBit]
  · have current := non_single_current_canonical statement witness valid (by simp [mode])
    have future := approval_next_canonical statement witness valid mode
    have same := approval_signer_count statement witness valid mode
    rw [slot_active_exact statement witness valid (by simp [mode]) slot]
    by_cases inactive : witness.authorization.current.signerCount ≤ slot.val
    · have c := current.2.2.2.2.2.2.2.2.2.2.2 slot.val inactive slot.isLt
      have n := future.2.2.2.2.2.2.2.2.2.2.2 slot.val (by omega) slot.isLt
      cases next <;> simp [c,n]
    · have active : slot.val < witness.authorization.current.signerCount := by omega
      simp [authBit,active]
  · cases next
    · have current := non_single_current_canonical statement witness valid (by simp [mode])
      rw [slot_active_exact statement witness valid (by simp [mode]) slot]
      by_cases inactive : witness.authorization.current.signerCount ≤ slot.val
      · have c := current.2.2.2.2.2.2.2.2.2.2.2 slot.val inactive slot.isLt
        simp [c]
      · have active : slot.val < witness.authorization.current.signerCount := by omega
        simp [authBit,active]
    · simp [authModeFlag,authBit]

theorem inactive_tag (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 6) (limb : Fin 5) :
    (wordAt (witness.authorization.policySignerTags.getD slot.val []) limb.val : F) *
      (((authModeFlag witness.authorization.mode 1 : F) +
        (authModeFlag witness.authorization.mode 2 : F)) *
      (1-(authSlotActive witness.authorization slot.val : F))) = 0 := by
  by_cases single : witness.authorization.mode = .singleKey
  · simp [authModeFlag,authBit,single]
  · have canonical := non_single_tags_canonical statement witness valid single
    rw [slot_active_exact statement witness valid single slot]
    by_cases inactive : witness.authorization.current.signerCount ≤ slot.val
    · have zero := canonical.2.2.2.2 slot.val inactive slot.isLt
      rw [zero_words_readback _ zero limb.val,Nat.cast_zero,zero_mul]
    · have active : slot.val < witness.authorization.current.signerCount := by omega
      simp [authBit,active]

end
end HegemonCrypto.SmallWood.V8Smz9SourceAuthLastCore
