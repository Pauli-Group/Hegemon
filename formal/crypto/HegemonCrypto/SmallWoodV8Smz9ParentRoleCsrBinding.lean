import HegemonCrypto.SmallWoodV8Smz9ParentRoleCsrSymbolic
import HegemonCrypto.SmallWoodV8Smz9ParentRoleCsrReadbacks
import HegemonCrypto.SmallWoodV8Smz9SourceStableLiveRoleCsr

namespace HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrBinding

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceParentLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceStableLiveRoleCsr
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrTable
open HegemonCrypto.SmallWood.V8Smz9SourceLiveCsrCoefficients
open HegemonCrypto.SmallWood.V8Smz9SourceRoleCsrFieldTerms
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrSymbolic
open HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrReadbacks
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (F)
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership (encoded_input_flag)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

def typedParentAnyInput (statement : V8PublicStatement) : F :=
  (flagAt statement.inputFlags 0 : F) + (flagAt statement.inputFlags 1 : F) -
    (flagAt statement.inputFlags 0 : F) * (flagAt statement.inputFlags 1 : F)

def typedParentExtraContribution (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (offset limb : Nat) : F :=
  let auth := witness.authorization
  let unit : F := sourceUnitWord limb
  if offset = 0 then
    -typedParentAnyInput statement * (if limb < 4 then
      (flagAt statement.inputFlags 0 : F) * (stableSourceWord statement witness (112 + limb) : F) +
      (1 - (flagAt statement.inputFlags 0 : F)) * (flagAt statement.inputFlags 1 : F) *
        (stableSourceWord statement witness (116 + limb) : F) else 0)
  else if offset = 1 then
    -(authPolicyWord auth hashes limb : F) +
      ((authModeFlag auth.mode 1 : F) + (authModeFlag auth.mode 2 : F)) * unit
  else if offset = 2 then
    -(wordAt auth.current.intentDigest limb : F) +
      ((authModeFlag auth.mode 1 : F) + (authModeFlag auth.mode 2 : F)) * unit
  else
    -((if limb < 5 then wordAt (auth.policySignerTags.getD (offset - 3) []) limb else 0 : Nat) : F) +
      (authSlotActive auth (offset - 3) : F) * unit

def typedParentTargetContribution (statement : V8PublicStatement) (offset limb : Nat) : F :=
  if offset = 0 then (1 - typedParentAnyInput statement) * (sourceUnitWord limb : F)
  else (sourceUnitWord limb : F)

theorem typed_parent_role_algebra (statement : V8PublicStatement) (witness : V8Witness)
    (hashes : AuthHashFinals) (offset limb : Nat) :
    parentLinearRoleValue statement witness hashes offset limb +
      typedParentExtraContribution statement witness hashes offset limb -
      typedParentTargetContribution statement offset limb = 0 := by
  unfold parentLinearRoleValue typedParentExtraContribution typedParentTargetContribution typedParentAnyInput
  split_ifs <;> ring

theorem parent_public_inputs (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    liveTypedPub statement 0 = (flagAt statement.inputFlags 0 : F) ∧
    liveTypedPub statement 1 = (flagAt statement.inputFlags 1 : F) := by
  exact ⟨congrArg (fun value : Nat => (value : F))
      (encoded_input_flag statement valid.1 (by decide : 0 < 2)),
    congrArg (fun value : Nat => (value : F))
      (encoded_input_flag statement valid.1 (by decide : 1 < 2))⟩

theorem parent_any_input_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) :
    liveAnyInput (liveTypedPub statement) = typedParentAnyInput statement := by
  obtain ⟨first,second⟩ := parent_public_inputs statement witness valid
  simp only [liveAnyInput, first, second, typedParentAnyInput]

theorem parent_target_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset limb : Nat) :
    parentRoleTargetContribution (liveTypedPub statement) offset limb =
      typedParentTargetContribution statement offset limb := by
  rw [parentRoleTargetContribution, typedParentTargetContribution,
    parent_any_input_field statement witness valid]
  by_cases off : offset = 0 <;> by_cases zero : limb = 0 <;>
    simp [off, zero, sourceUnitWord]

theorem parent_extra_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 9) (limb : Fin 7) :
    parentRoleExtraContribution (liveTypedPub statement) (parentCandidateField statement witness)
      offset.val limb.val =
      typedParentExtraContribution statement witness (typedSourceFinals statement witness) offset.val limb.val := by
  have anyInput := parent_any_input_field statement witness valid
  obtain ⟨public0,public1⟩ := parent_public_inputs statement witness valid
  have mode1 : parentCandidateField statement witness 5952 =
      (authModeFlag witness.authorization.mode 1 : F) := parent_mode_field statement witness ⟨1,by decide⟩
  have mode2 : parentCandidateField statement witness 6016 =
      (authModeFlag witness.authorization.mode 2 : F) := parent_mode_field statement witness ⟨2,by decide⟩
  by_cases off0 : offset.val = 0
  · simp only [parentRoleExtraContribution, typedParentExtraContribution, if_pos off0]
    by_cases low : limb.val < 4
    · have read0 : parentCandidateField statement witness (41520 + limb.val) =
          (stableSourceWord statement witness (112 + limb.val) : F) :=
        parent_spend_field statement witness ⟨0,by decide⟩ ⟨limb.val,low⟩
      have read1 : parentCandidateField statement witness (41524 + limb.val) =
          (stableSourceWord statement witness (116 + limb.val) : F) :=
        parent_spend_field statement witness ⟨1,by decide⟩ ⟨limb.val,low⟩
      simp only [if_pos low]
      rw [read0, read1, public0, public1, anyInput]
      ring
    · simp only [if_neg low, mul_zero]
  by_cases off1 : offset.val = 1
  · simp only [parentRoleExtraContribution, typedParentExtraContribution, if_neg off0, if_pos off1]
    rw [parent_policy_field statement witness limb]
    by_cases zero : limb.val = 0 <;> simp [zero, sourceUnitWord, mode1, mode2]
  by_cases off2 : offset.val = 2
  · simp only [parentRoleExtraContribution, typedParentExtraContribution,
      if_neg off0, if_neg off1, if_pos off2]
    rw [parent_intent_field statement witness limb]
    by_cases zero : limb.val = 0 <;> simp [zero, sourceUnitWord, mode1, mode2]
  · have lower : 3 ≤ offset.val := by omega
    let slot : Fin 6 := ⟨offset.val - 3,by omega⟩
    have tag :
        (if limb.val < 5 then parentCandidateField statement witness
          ((196 + 5 * (offset.val - 3) + limb.val) * 64) else 0) =
        ((if limb.val < 5 then wordAt
          (witness.authorization.policySignerTags.getD (offset.val - 3) []) limb.val else 0 : Nat) : F) := by
      by_cases low : limb.val < 5
      · simp only [if_pos low]
        exact parent_tag_field statement witness slot ⟨limb.val,low⟩
      · simp only [if_neg low, Nat.cast_zero]
    have signers := parent_signer_sum_field statement witness slot
    simp only [parentRoleExtraContribution, typedParentExtraContribution,
      if_neg off0, if_neg off1, if_neg off2]
    rw [tag]
    by_cases zero : limb.val = 0
    · simp only [sourceUnitWord, if_pos zero, Nat.cast_one, mul_one]
      exact congrArg (fun value : F => -((if limb.val < 5 then wordAt
        (witness.authorization.policySignerTags.getD (offset.val - 3) []) limb.val else 0 : Nat) : F) + value) signers
    · simp only [sourceUnitWord, if_neg zero, Nat.cast_zero, mul_zero]

theorem parent_role_kernel_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 9) (limb : Fin 7) :
    roleCsrFieldKernel (liveTypedPub statement) (parentCandidateField statement witness)
      (21 + offset.val) limb.val = 0 := by
  rw [parent_role_field_kernel_shape, parent_role_field statement witness valid offset limb,
    parent_extra_field statement witness valid offset limb, parent_target_field statement witness valid]
  exact typed_parent_role_algebra statement witness (typedSourceFinals statement witness) offset.val limb.val

theorem parent_actual_role_csr_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 9) (limb : Fin 7) :
    actualCsrResidual (liveTypedPub statement) (fullTypedSourceCandidate statement witness)
      (expectedLiveCsrAttempt .roles ((21 + offset.val) * 7 + limb.val)) = 0 := by
  rw [actual_role_csr_as_field_kernel (liveTypedPub statement)
    (fullTypedSourceCandidate statement witness) ⟨21 + offset.val,by omega⟩ limb]
  exact parent_role_kernel_zero statement witness valid offset limb


end
end HegemonCrypto.SmallWood.V8Smz9ParentRoleCsrBinding
