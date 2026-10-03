import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootInputs
import HegemonCrypto.SmallWoodV8Smz9SourceAuthInputSelection

namespace HegemonCrypto.SmallWood.V8Smz9SourceParentLiveRoleCsr

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SourceAuthInputSelection

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem valid_current_signer_count_bound (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    witness.authorization.current.signerCount ≤ 6 := by
  have auth := valid.2.2.1.2.2
  cases mode : witness.authorization.mode with
  | singleKey =>
      simp only [V8AuthorizationValid, mode] at auth
      obtain ⟨_,_,_,_,_,count,_⟩ := auth.1
      omega
  | approvalStep =>
      simp only [V8AuthorizationValid, mode] at auth
      exact auth.2.2.1.2.2.2.2.2.2.1
  | finalThresholdSpend =>
      simp only [V8AuthorizationValid, mode] at auth
      exact auth.2.1.2.2.2.2.2.2.1

/-- The finite sum in the actual source, not an assumed activity bit. -/
theorem auth_slot_active_formula (auth : V8AuthorizationWitness)
    (countBound : auth.current.signerCount ≤ 6) (slot : Fin 6) :
    authSlotActive auth slot.val =
      if auth.mode = .singleKey then 0 else if slot.val < auth.current.signerCount then 1 else 0 := by
  have finite : ∀ mode : V8AuthorizationMode, ∀ count : Fin 7, ∀ slot : Fin 6,
      ((List.range (6 - slot.val)).map fun offset =>
        if mode = .singleKey then 0 else if count.val = slot.val + offset + 1 then 1 else 0).sum =
      if mode = .singleKey then 0 else if slot.val < count.val then 1 else 0 := by
    intro mode
    cases mode <;> decide
  exact finite auth.mode ⟨auth.current.signerCount,by omega⟩ slot

theorem valid_auth_slot_boolean (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 6) :
    BooleanWord (authSlotActive witness.authorization slot.val) := by
  rw [auth_slot_active_formula _ (valid_current_signer_count_bound statement witness valid) slot]
  split_ifs <;> simp [BooleanWord]

theorem valid_nonsingle_signer_tags (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (nonsingle : witness.authorization.mode ≠ .singleKey) :
    CanonicalSignerTags witness.authorization := by
  have auth := valid.2.2.1.2.2
  cases mode : witness.authorization.mode with
  | singleKey => exact False.elim (nonsingle mode)
  | approvalStep =>
      simp only [V8AuthorizationValid, mode] at auth
      exact auth.2.2.2.2.1
  | finalThresholdSpend =>
      simp only [V8AuthorizationValid, mode] at auth
      exact auth.2.2.2.1

theorem valid_inactive_tag_word_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 6)
    (inactive : authSlotActive witness.authorization slot.val = 0) (limb : Nat) :
    wordAt (witness.authorization.policySignerTags.getD slot.val []) limb = 0 := by
  by_cases single : witness.authorization.mode = .singleKey
  · exact zero_tag_readback _ (single_zero_openings statement witness valid single).2.2 _ _
  · have formula := auth_slot_active_formula witness.authorization
      (valid_current_signer_count_bound statement witness valid) slot
    rw [if_neg single] at formula
    have past : witness.authorization.current.signerCount ≤ slot.val := by
      by_contra below
      have less : slot.val < witness.authorization.current.signerCount := by omega
      rw [if_pos less] at formula
      omega
    have zero := (valid_nonsingle_signer_tags statement witness valid single).2.2.2.2
      slot.val past slot.isLt
    exact zero_words_readback _ zero limb

theorem valid_tag_word_truncation (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (slot : Fin 6) (limb : Nat) :
    (if limb < 5 then wordAt (witness.authorization.policySignerTags.getD slot.val []) limb else 0) =
      wordAt (witness.authorization.policySignerTags.getD slot.val []) limb := by
  by_cases low : limb < 5
  · rw [if_pos low]
  · rw [if_neg low]
    have shape := (typed_valid_authorization_geometry statement witness valid).2.2.2 slot.val slot.isLt
    exact (List.getD_eq_default _ 0 (by omega)).symm

theorem valid_spend_word_truncation (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (limb : Nat) :
    wordAt (witness.inputs.getD input.val default).spendKey limb =
      if limb < 4 then stableSourceWord statement witness (112 + input.val * 4 + limb) else 0 := by
  by_cases low : limb < 4
  · rw [if_pos low]
    exact (stable_source_spend_key_readback statement witness input ⟨limb,low⟩).symm
  · rw [if_neg low]
    have shape := (valid_input_spend_words_exact statement witness valid input.val input.isLt).1
    exact List.getD_eq_default _ 0 (by omega)

noncomputable section

def parentLinearRoleValue (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (offset limb : Nat) : F :=
  let f0 : F := flagAt statement.inputFlags 0
  let f1 : F := flagAt statement.inputFlags 1
  let anyInput := f0 + f1 - f0 * f1
  let unit : F := sourceUnitWord limb
  let auth := witness.authorization
  if offset = 0 then
    anyInput * (if limb < 4 then
      f0 * (stableSourceWord statement witness (112 + limb) : F) +
      (1 - f0) * f1 * (stableSourceWord statement witness (116 + limb) : F) else 0) +
      (1 - anyInput) * unit
  else if offset = 1 then
    (authPolicyWord auth hashes limb : F) +
      (1 - (authModeFlag auth.mode 1 : F) - (authModeFlag auth.mode 2 : F)) * unit
  else if offset = 2 then
    (wordAt auth.current.intentDigest limb : F) +
      (1 - (authModeFlag auth.mode 1 : F) - (authModeFlag auth.mode 2 : F)) * unit
  else
    ((if limb < 5 then wordAt (auth.policySignerTags.getD (offset - 3) []) limb else 0 : Nat) : F) +
      (1 - (authSlotActive auth (offset - 3) : F)) * unit

theorem source_parent_input_role_linear (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (limb : Fin 7) :
    (sourceRoleWord statement witness hashes 21 limb.val : F) =
      parentLinearRoleValue statement witness hashes 0 limb.val := by
  have read0 := valid_spend_word_truncation statement witness valid ⟨0,by decide⟩ limb.val
  have read1 := valid_spend_word_truncation statement witness valid ⟨1,by decide⟩ limb.val
  dsimp only at read0 read1
  rcases typed_input_flag_boolean statement witness valid ⟨0,by decide⟩ with first | first <;>
    rcases typed_input_flag_boolean statement witness valid ⟨1,by decide⟩ with second | second
  all_goals dsimp only at first second
  all_goals by_cases low : limb.val < 4
  all_goals simp [sourceRoleWord, parentLinearRoleValue, selectedTransactionSpendKey,
    first, second, low]
  all_goals first
    | simpa [low, List.getD_eq_getElem?_getD] using
        (congrArg (fun value : Nat => (value : F)) read0)
    | simpa [low, List.getD_eq_getElem?_getD] using
        (congrArg (fun value : Nat => (value : F)) read1)

theorem source_parent_policy_role_linear (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (limb : Fin 7) :
    (sourceRoleWord statement witness hashes 22 limb.val : F) =
      parentLinearRoleValue statement witness hashes 1 limb.val := by
  cases mode : witness.authorization.mode <;>
    simp [sourceRoleWord, parentLinearRoleValue, authPolicyWord, authModeFlag, authBit, mode]

theorem source_parent_intent_role_linear (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals) (limb : Fin 7) :
    (sourceRoleWord statement witness hashes 23 limb.val : F) =
      parentLinearRoleValue statement witness hashes 2 limb.val := by
  cases mode : witness.authorization.mode with
  | singleKey =>
      have zero := zero_words_readback _
        (single_zero_openings statement witness valid mode).1.2.2.2.1 limb.val
      simp [sourceRoleWord, parentLinearRoleValue, authModeFlag, authBit, mode, zero]
  | approvalStep =>
      simp [sourceRoleWord, parentLinearRoleValue, authModeFlag, authBit, mode]
  | finalThresholdSpend =>
      simp [sourceRoleWord, parentLinearRoleValue, authModeFlag, authBit, mode]

theorem source_parent_tag_role_linear (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (slot : Fin 6) (limb : Fin 7) :
    (sourceRoleWord statement witness hashes (24 + slot.val) limb.val : F) =
      parentLinearRoleValue statement witness hashes (3 + slot.val) limb.val := by
  have no0 : 3 + slot.val ≠ 0 := by omega
  have no1 : 3 + slot.val ≠ 1 := by omega
  have no2 : 3 + slot.val ≠ 2 := by omega
  have address : 3 + slot.val - 3 = slot.val := by omega
  have roleAddress : 24 + slot.val - 24 = slot.val := by omega
  simp only [parentLinearRoleValue, if_neg no0, if_neg no1, if_neg no2, address]
  rw [valid_tag_word_truncation statement witness valid slot limb.val]
  rcases valid_auth_slot_boolean statement witness valid slot with inactive | active
  · have zero := valid_inactive_tag_word_zero statement witness valid slot inactive limb.val
    simp [sourceRoleWord, show ¬24 + slot.val < 21 by omega,
      show 24 + slot.val ≠ 21 by omega, show 24 + slot.val ≠ 22 by omega,
      show 24 + slot.val ≠ 23 by omega, show 24 + slot.val < 30 by omega,
      roleAddress, inactive]
    simpa only [List.getD_eq_getElem?_getD, Nat.cast_zero] using
      (congrArg (fun value : Nat => (value : F)) zero)
  · simp [sourceRoleWord, show ¬24 + slot.val < 21 by omega,
      show 24 + slot.val ≠ 21 by omega, show 24 + slot.val ≠ 22 by omega,
      show 24 + slot.val ≠ 23 by omega, show 24 + slot.val < 30 by omega,
      roleAddress, active]

/-- All 63 parent-role cells, with the same arbitrary hash-final accessor on both sides. -/
theorem source_parent_live_role_linear (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (hashes : AuthHashFinals)
    (offset : Fin 9) (limb : Fin 7) :
    (sourceRoleWord statement witness hashes (21 + offset.val) limb.val : F) =
      parentLinearRoleValue statement witness hashes offset.val limb.val := by
  by_cases zero : offset.val = 0
  · simpa only [zero] using source_parent_input_role_linear statement witness valid hashes limb
  by_cases one : offset.val = 1
  · simpa only [one] using source_parent_policy_role_linear statement witness hashes limb
  by_cases two : offset.val = 2
  · simpa only [two] using source_parent_intent_role_linear statement witness valid hashes limb
  have low : 3 ≤ offset.val := by omega
  have result := source_parent_tag_role_linear statement witness valid hashes
    ⟨offset.val - 3,by omega⟩ limb
  have a : 24 + (offset.val - 3) = 21 + offset.val := by omega
  have b : 3 + (offset.val - 3) = offset.val := by omega
  simpa only [a,b] using result


end
end HegemonCrypto.SmallWood.V8Smz9SourceParentLiveRoleCsr
