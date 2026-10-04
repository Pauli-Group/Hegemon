import HegemonCrypto.SmallWoodV8Smz9SourceParentLiveRoleCsr
import HegemonCrypto.SmallWoodV8Smz9SourceAuthRootInputs
import HegemonCrypto.SmallWoodV8Smz9SourceTailCsrReadbacks

namespace HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrReadbacks

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceAuthRootInputs
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceParentLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField_eq_packedWord)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

def parentCandidateField (statement : V8PublicStatement) (witness : V8Witness)
    (address : Nat) : F := (fullTypedSourceCandidate statement witness).getD address 0

/-- One generic family readback replaces expansion of the full candidate. -/
theorem parent_auth_family_field (statement : V8PublicStatement) (witness : V8Witness)
    (family : AuthFamily) (index : Nat) (bound : index < family.width) :
    parentCandidateField statement witness ((92 + family.base + index) * 64) =
      (authFamilyWord statement witness (typedSourceFinals statement witness) family index : F) := by
  have result := full_candidate_auth_family statement witness family index bound ⟨0,by decide⟩
  have extent := auth_family_extent_bound family
  rw [laneField_eq_packedWord _ _ _ (by omega)] at result
  exact result

theorem parent_policy_field (statement : V8PublicStatement) (witness : V8Witness) (limb : Fin 7) :
    parentCandidateField statement witness ((138 + limb.val) * 64) =
      (authPolicyWord witness.authorization (typedSourceFinals statement witness) limb.val : F) := by
  exact parent_auth_family_field statement witness .policy limb.val limb.isLt

theorem parent_intent_field (statement : V8PublicStatement) (witness : V8Witness) (limb : Fin 7) :
    parentCandidateField statement witness ((145 + limb.val) * 64) =
      (wordAt witness.authorization.current.intentDigest limb.val : F) := by
  exact parent_auth_family_field statement witness .intent limb.val limb.isLt

theorem parent_mode_field (statement : V8PublicStatement) (witness : V8Witness) (mode : Fin 3) :
    parentCandidateField statement witness ((92 + mode.val) * 64) =
      (authModeFlag witness.authorization.mode mode.val : F) := by
  exact parent_auth_family_field statement witness .mode mode.val mode.isLt

theorem parent_tag_field (statement : V8PublicStatement) (witness : V8Witness)
    (slot : Fin 6) (limb : Fin 5) :
    parentCandidateField statement witness ((196 + 5 * slot.val + limb.val) * 64) =
      (wordAt (witness.authorization.policySignerTags.getD slot.val []) limb.val : F) := by
  have result := parent_auth_family_field statement witness .policyTag
    (5 * slot.val + limb.val) (by change 5 * slot.val + limb.val < 30; omega)
  have quotient : (5 * slot.val + limb.val) / 5 = slot.val := by omega
  have remainder : (5 * slot.val + limb.val) % 5 = limb.val := by omega
  have address : (92 + AuthFamily.policyTag.base + (5 * slot.val + limb.val)) * 64 =
      (196 + 5 * slot.val + limb.val) * 64 := by simp only [AuthFamily.base]; omega
  rw [address] at result
  simpa only [authFamilyWord, quotient, remainder] using result

theorem parent_signer_field (statement : V8PublicStatement) (witness : V8Witness) (slot : Fin 6) :
    parentCandidateField statement witness ((176 + slot.val) * 64) =
      (authSignerFlag witness.authorization slot.val : F) := by
  exact parent_auth_family_field statement witness .signerFlag slot.val slot.isLt

theorem nat_list_sum_field (values : List Nat) :
    (values.sum : F) = (values.map fun (value : Nat) => (value : F)).sum := by
  induction values with
  | nil => simp
  | cons head tail ih => simp [ih, Nat.cast_add]

/-- Actual finite signer-flag sum; no Boolean or count premise is needed. -/
theorem auth_slot_active_field_sum (auth : V8AuthorizationWitness) (slot : Nat) :
    (authSlotActive auth slot : F) =
      ((List.range (6 - slot)).map fun offset => (authSignerFlag auth (slot + offset) : F)).sum := by
  change (((List.range (6 - slot)).map fun offset => authSignerFlag auth (slot + offset)).sum : F) = _
  simpa only [List.map_map, Function.comp_def] using
    nat_list_sum_field ((List.range (6 - slot)).map fun offset => authSignerFlag auth (slot + offset))

theorem parent_signer_sum_field (statement : V8PublicStatement) (witness : V8Witness) (slot : Fin 6) :
    ((List.range (6 - slot.val)).map fun offset =>
      parentCandidateField statement witness ((176 + slot.val + offset) * 64)).sum =
      (authSlotActive witness.authorization slot.val : F) := by
  rw [auth_slot_active_field_sum]
  congr 1
  apply List.map_congr_left
  intro offset member
  have bound := List.mem_range.mp member
  simpa only [Nat.add_assoc] using
    parent_signer_field statement witness ⟨slot.val + offset,by omega⟩

theorem parent_spend_field (statement : V8PublicStatement) (witness : V8Witness)
    (input : Fin 2) (limb : Fin 4) :
    parentCandidateField statement witness (41520 + input.val * 4 + limb.val) =
      (stableSourceWord statement witness (112 + input.val * 4 + limb.val) : F) := by
  have result := congrArg (fun value : Nat => (value : F))
    (full_candidate_source_word_readback statement witness ⟨112 + input.val * 4 + limb.val,by omega⟩)
  have address : 41408 + (112 + input.val * 4 + limb.val) = 41520 + input.val * 4 + limb.val := by omega
  change ((fullTypedSourceCandidate statement witness).getD (41520 + input.val * 4 + limb.val) 0 : F) = _
  simpa only [address] using result

theorem parent_role_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 9) (limb : Fin 7) :
    parentCandidateField statement witness (41536 + (21 + offset.val) + 64 * limb.val) =
      parentLinearRoleValue statement witness (typedSourceFinals statement witness) offset.val limb.val := by
  have result := full_candidate_tail_flat_field_readback statement witness .roleDifference
    limb.val limb.isLt ⟨21 + offset.val,by omega⟩
  have address : (647 + TailFamily.roleDifference.base + limb.val) * 64 + (21 + offset.val) =
      41536 + (21 + offset.val) + 64 * limb.val := by simp only [TailFamily.base]; omega
  rw [address] at result
  exact result.trans (source_parent_live_role_linear statement witness valid
    (typedSourceFinals statement witness) offset limb)


end
end HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrReadbacks
