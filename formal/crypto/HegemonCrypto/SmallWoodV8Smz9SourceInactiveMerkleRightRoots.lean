import HegemonCrypto.SmallWoodV8Smz9SourceInactiveMerkleRightReadback

/-! Actual family-17 forward residuals. The actual CSR coefficient DAG and
raw attempt table are selected internally. This is a 448-entry subset,
not packed acceptance, a Rust refinement, or production authority. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem exact_inactive_right_attempt_lookup (input : Fin 2) (level : Fin 32) (limb : Fin 7) :
    exactCsrAttempts[17838 + (224 * input.val + 7 * level.val + limb.val)]? =
      some (inactiveSiblingExpectedAttempt input.val level.val limb.val) :=
  exact_attempt_lookup _ (exact_inactive_sibling_attempts input.val input.isLt
    level.val level.isLt limb.val limb.isLt).1

theorem actual_inactive_right_coefficient (pub : Nat → F) (input : Fin 2) :
    actualCsrCoefficients pub (124 + input.val) = 1 - pub input.val := by
  have nodes := exact_inactive_coefficient_nodes input.val (by omega)
  have publicEquation := actual_csr_node_field_equation pub nodes.1
  have gateEquation := actual_csr_node_field_equation pub nodes.2.1
  simpa only [expressionField, (actual_csr_zero_one pub).2, publicEquation] using gateEquation

theorem actual_inactive_right_residual (pub : Nat → F) (packed : List Nat)
    (input : Fin 2) (level : Fin 32) (limb : Fin 7) :
    actualCsrResidual pub packed (inactiveSiblingExpectedAttempt input.val level.val limb.val) =
      (1 - pub input.val) * (packed.getD (inlineRightAddress input.val level.val limb.val) 0 : F) := by
  simp only [actualCsrResidual, actualCsrTerms, inactiveSiblingExpectedAttempt, attempt,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    actual_inactive_right_coefficient pub input, (actual_csr_zero_one pub).1, add_zero, sub_zero]

theorem full_candidate_inactive_right_residual_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Fin 2) (level : Fin 32) (limb : Fin 7) :
    actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
      (fullTypedSourceCandidate statement witness)
      (inactiveSiblingExpectedAttempt input.val level.val limb.val) = 0 := by
  rw [actual_inactive_right_residual, encoded_input_flag statement valid.1 input.isLt]
  have flagBoolean := boolean_getD statement.inputFlags valid.1.2.2.1 input.val
  change flagAt statement.inputFlags input.val = 0 ∨ flagAt statement.inputFlags input.val = 1 at flagBoolean
  rcases flagBoolean with inactive | active
  · rw [full_candidate_inactive_right_zero statement witness valid input level limb inactive]
    simp only [Nat.cast_zero, mul_zero]
  · rw [active]
    simp only [Nat.cast_one, sub_self, zero_mul]

def inactiveRightInput (offset : Fin 448) : Fin 2 := ⟨offset.val / 224, by omega⟩
def inactiveRightLevel (offset : Fin 448) : Fin 32 := ⟨(offset.val % 224) / 7, by omega⟩
def inactiveRightLimb (offset : Fin 448) : Fin 7 := ⟨offset.val % 7, Nat.mod_lt _ (by decide)⟩

theorem inactive_right_offset_decomposition (offset : Fin 448) :
    224 * (inactiveRightInput offset).val + 7 * (inactiveRightLevel offset).val +
      (inactiveRightLimb offset).val = offset.val := by
  simp only [inactiveRightInput, inactiveRightLevel, inactiveRightLimb]
  omega

def inactiveRightAttempt (offset : Fin 448) : CsrExecutableAttempt :=
  inactiveSiblingExpectedAttempt (inactiveRightInput offset).val
    (inactiveRightLevel offset).val (inactiveRightLimb offset).val

theorem exact_inactive_right_all_448_lookup (offset : Fin 448) :
    exactCsrAttempts[17838 + offset.val]? = some (inactiveRightAttempt offset) := by
  have found := exact_inactive_right_attempt_lookup (inactiveRightInput offset)
    (inactiveRightLevel offset) (inactiveRightLimb offset)
  rw [inactive_right_offset_decomposition] at found
  exact found

theorem inactive_right_all_448_metadata (offset : Fin 448) :
    (inactiveRightAttempt offset).globalIndex = 17838 + offset.val ∧
    (inactiveRightAttempt offset).family = 17 ∧
    (inactiveRightAttempt offset).localIndex = offset.val ∧
    (inactiveRightAttempt offset).emission = 1 ∧
    (inactiveRightAttempt offset).targetRoot = 0 := by
  simp only [inactiveRightAttempt, inactiveSiblingExpectedAttempt, attempt,
    inactive_right_offset_decomposition, and_self]

theorem full_candidate_inactive_right_all_448_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 448) :
    actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
      (fullTypedSourceCandidate statement witness) (inactiveRightAttempt offset) = 0 :=
  full_candidate_inactive_right_residual_zero statement witness valid (inactiveRightInput offset)
    (inactiveRightLevel offset) (inactiveRightLimb offset)

theorem full_candidate_actual_inactive_right_all_448_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (offset : Fin 448) :
    ∃ entry, exactCsrAttempts[17838 + offset.val]? = some entry ∧ entry.family = 17 ∧
      entry.localIndex = offset.val ∧
      actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (fullTypedSourceCandidate statement witness) entry = 0 := by
  exact ⟨inactiveRightAttempt offset, exact_inactive_right_all_448_lookup offset,
    (inactive_right_all_448_metadata offset).2.1,
    (inactive_right_all_448_metadata offset).2.2.1,
    full_candidate_inactive_right_all_448_zero statement witness valid offset⟩


end
end HegemonCrypto.SmallWood.V8Smz9SourceInactiveMerkleRight

