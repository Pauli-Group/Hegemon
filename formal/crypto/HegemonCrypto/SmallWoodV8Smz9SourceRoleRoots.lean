import HegemonCrypto.SmallWoodV8Smz9SourceRoleAlgebra
import HegemonCrypto.SmallWoodV8Smz9SourceRoleNonzero

namespace HegemonCrypto.SmallWood.V8Smz9SourceRoleRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldInverse)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceRoleAlgebra
open HegemonCrypto.SmallWood.V8Smz9SourceRoleNonzero
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem typed_selected_role_nonzero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Nat) :
    sourceRoleWord statement witness (typedSourceFinals statement witness) role
      (sourceRoleSelector statement witness (typedSourceFinals statement witness) role) ≠ 0 :=
  first_nonzero_selected _ (typed_source_role_nonzero statement witness valid role)

noncomputable section

theorem typed_role_inverse_equation (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Nat) :
    (sourceRoleInverse statement witness (typedSourceFinals statement witness) role : F) *
      (sourceRoleWord statement witness (typedSourceFinals statement witness) role
        (sourceRoleSelector statement witness (typedSourceFinals statement witness) role) : F) = 1 := by
  apply selected_inverse_equation
  · intro limb
    exact valid_role_word_canonical statement witness valid _
      (typed_source_finals_canonical statement witness) role limb.val
  · exact typed_source_role_nonzero statement witness valid role

theorem full_candidate_role_field_readback (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) (limb : Fin 7) :
    laneField (fullTypedSourceCandidate statement witness) lane.val (649 + limb.val) =
      (sourceRoleWord statement witness (typedSourceFinals statement witness) lane.val limb.val : F) := by
  have readback := full_candidate_tail_family_readback statement witness .roleDifference
    limb.val limb.isLt lane
  exact congrArg (fun word : Nat => (word : F)) readback

theorem full_candidate_selector_field_readback (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val 656 =
      (sourceRoleSelector statement witness (typedSourceFinals statement witness) lane.val : F) := by
  have readback := full_candidate_tail_family_readback statement witness .roleSelector 0 (by decide) lane
  exact congrArg (fun word : Nat => (word : F)) readback

theorem full_candidate_inverse_field_readback (statement : V8PublicStatement) (witness : V8Witness)
    (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val 657 =
      (sourceRoleInverse statement witness (typedSourceFinals statement witness) lane.val : F) := by
  have readback := full_candidate_tail_family_readback statement witness .roleInverse 0 (by decide) lane
  exact congrArg (fun word : Nat => (word : F)) readback

/-- Position803's actual selector-domain root needs no semantic validity. -/
theorem full_candidate_selector_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (publicWords : List Nat) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions (fun index => (publicWords.getD index 0 : F))
      (laneField (fullTypedSourceCandidate statement witness) lane.val) 8009 = 0 := by
  rw [(actual_role_root_formulas _ _).1, full_candidate_selector_field_readback]
  exact selector_polynomial_zero
    ⟨sourceRoleSelector statement witness (typedSourceFinals statement witness) lane.val,
      source_role_selector_bound statement witness _ lane.val⟩

/-- Position804's actual inverse root follows from fixed validity, not a role premise. -/
theorem full_candidate_role_inverse_root_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (publicWords : List Nat) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions (fun index => (publicWords.getD index 0 : F))
      (laneField (fullTypedSourceCandidate statement witness) lane.val) 8128 = 0 := by
  rw [(actual_role_root_formulas _ _).2, full_candidate_selector_field_readback,
    full_candidate_inverse_field_readback]
  let selected : Fin 7 :=
    ⟨sourceRoleSelector statement witness (typedSourceFinals statement witness) lane.val,
      source_role_selector_bound statement witness _ lane.val⟩
  rw [selection_polynomial_readback selected, full_candidate_role_field_readback statement witness lane selected,
    typed_role_inverse_equation statement witness valid lane.val, sub_self]

theorem full_candidate_actual_role_roots_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (publicWords : List Nat)
    (lane : Fin 64) (offset : Fin 2) :
    (exactNonlinearRoots[803 + offset.val]?).map
      (fieldAt exactNonlinearExpressions (fun index => (publicWords.getD index 0 : F))
        (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  fin_cases offset
  · simp only [Nat.add_zero, actual_role_root_indices.1, Option.map_some,
      full_candidate_selector_root_zero]
  · simp only [Nat.reduceAdd, actual_role_root_indices.2, Option.map_some,
      full_candidate_role_inverse_root_zero statement witness valid]

/-- Negative control: selector validity alone does not rescue an all-zero role. -/
theorem all_zero_role_inverse_rejected :
    (fieldInverse 0 : F) * roleSelectedPolynomial
      (firstNonzeroSeven (fun _ => 0) : F) (fun _ => 0) - 1 ≠ 0 := by
  norm_num [firstNonzeroSeven, roleSelectedPolynomial]

end


end HegemonCrypto.SmallWood.V8Smz9SourceRoleRoots
