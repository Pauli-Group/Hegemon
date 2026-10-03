import HegemonCrypto.SmallWoodV8Smz9SourcePrfFrames
import HegemonCrypto.SmallWoodV8Smz9SourceMerkleCopies
import HegemonCrypto.SmallWoodV8Smz9SemanticAssetMembership

namespace HegemonCrypto.SmallWood.V8Smz9SourcePrfInitial
open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SourceMerkleCopies
open HegemonCrypto.SmallWood.V8Smz9SourceDenseCsr
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

def prfInitialAttempt (lane : Nat) : CsrExecutableAttempt :=
  if lane < 4 then decodedKeyExpectedAttempt lane else prfFrameAttempt lane

theorem exact_prf_initial_lookup (lane : Fin 16) :
    exactCsrAttempts[15789 + lane.val]? = some (prfInitialAttempt lane.val) := by
  by_cases rate : lane.val < 4
  · rw [prfInitialAttempt, if_pos rate]
    exact exact_attempt_lookup _ (exact_key_bridge_attempts.1 lane.val rate)
  · rw [prfInitialAttempt, if_neg rate]
    exact exact_attempt_lookup _ (prf_frame_source lane (by omega))

theorem key_word_address_is_initial (limb : Nat) : keyWordAddress limb = hashInitialIndex 0 limb := by
  simp only [keyWordAddress, hashInitialIndex, hashRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, hashRowsPerGroup]
  omega

noncomputable section

theorem actual_prf_selected_coefficients (pub : Nat → F) :
    actualCsrCoefficients pub 196 = -pub 0 ∧
      actualCsrCoefficients pub 197 = -(pub 1 * (1 - pub 0)) := by
  have first := actual_csr_node_field_equation pub
    (show exactCsrExpressions[4]? = some (.publicWord 0) by decide)
  have second := actual_csr_node_field_equation pub
    (show exactCsrExpressions[5]? = some (.publicWord 1) by decide)
  have inactive := actual_csr_node_field_equation pub
    (show exactCsrExpressions[124]? = some (.sub 1 4) by decide)
  have selected := actual_csr_node_field_equation pub
    (show exactCsrExpressions[195]? = some (.mul 5 124) by decide)
  have negativeFirst := actual_csr_node_field_equation pub
    (show exactCsrExpressions[196]? = some (.sub 0 4) by decide)
  have negativeSecond := actual_csr_node_field_equation pub
    (show exactCsrExpressions[197]? = some (.sub 0 195) by decide)
  simp only [expressionField] at first second inactive selected negativeFirst negativeSecond
  rw [(actual_csr_zero_one pub).2, first] at inactive
  rw [second, inactive] at selected
  constructor
  · simpa only [(actual_csr_zero_one pub).1, first, zero_sub] using negativeFirst
  · simpa only [(actual_csr_zero_one pub).1, selected, zero_sub] using negativeSecond

theorem actual_prf_rate_residual (pub : Nat → F) (packed : List Nat) (limb : Nat) :
    actualCsrResidual pub packed (decodedKeyExpectedAttempt limb) =
      (packed.getD (hashInitialIndex 0 limb) 0 : F) -
      pub 0 * (packed.getD (41520 + limb) 0 : F) -
      (pub 1 * (1 - pub 0)) * (packed.getD (41524 + limb) 0 : F) := by
  simp only [actualCsrResidual, actualCsrTerms, decodedKeyExpectedAttempt, attempt,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    (actual_csr_zero_one pub).1, (actual_csr_zero_one pub).2,
    (actual_prf_selected_coefficients pub).1, (actual_prf_selected_coefficients pub).2,
    key_word_address_is_initial]
  ring

theorem actual_prf_padding_residual (pub : Nat → F) (packed : List Nat) (lane : Fin 16) :
    actualCsrResidual pub packed (prfFrameAttempt lane.val) =
      (packed.getD (hashInitialIndex 0 lane.val) 0 : F) - (prfFrameConstant lane.val : F) := by
  have target : actualCsrCoefficients pub (prfFrameTarget lane.val) = (prfFrameConstant lane.val : F) :=
    actual_csr_node_field_equation pub (prf_frame_constant_node lane)
  simp only [actualCsrResidual, actualCsrTerms, prfFrameAttempt, attempt,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    (actual_csr_zero_one pub).2, target, one_mul, add_zero]

theorem global_spend_key_selection_field (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 4) :
    ((globalSpendKey statement witness).getD limb.val 0 : F) =
      (flagAt statement.inputFlags 0 : F) * (wordAt (inputAt witness 0).spendKey limb.val : F) +
      (flagAt statement.inputFlags 1 : F) * (1 - (flagAt statement.inputFlags 0 : F)) *
        (wordAt (inputAt witness 1).spendKey limb.val : F) := by
  have first := boolean_getD statement.inputFlags valid.1.2.2.1 0
  have second := boolean_getD statement.inputFlags valid.1.2.2.1 1
  change statement.inputFlags.getD 0 0 = 0 ∨ statement.inputFlags.getD 0 0 = 1 at first
  change statement.inputFlags.getD 1 0 = 0 ∨ statement.inputFlags.getD 1 0 = 1 at second
  rcases first with firstZero | firstOne <;> rcases second with secondZero | secondOne <;>
    simp only [globalSpendKey, flagAt, *]
  all_goals simp [fixedWords, wordAt, limb.isLt]
  all_goals fin_cases limb <;> rfl

theorem full_candidate_prf_rate_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (limb : Fin 4) :
    actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
      (fullTypedSourceCandidate statement witness) (decodedKeyExpectedAttempt limb.val) = 0 := by
  have key0 := full_candidate_spend_keys_readback statement witness ⟨0, by decide⟩ limb
  have key1 := full_candidate_spend_keys_readback statement witness ⟨1, by decide⟩ limb
  norm_num only at key0 key1
  rw [actual_prf_rate_residual,
    full_candidate_prf_initial_field statement witness valid ⟨limb.val, by omega⟩,
    if_pos limb.isLt,
    key0, key1,
    encoded_input_flag statement valid.1 (by decide : 0 < 2),
    encoded_input_flag statement valid.1 (by decide : 1 < 2),
    global_spend_key_selection_field statement witness valid limb]
  change _ - _ * (wordAt (inputAt witness 0).spendKey limb.val : F) -
    _ * (wordAt (inputAt witness 1).spendKey limb.val : F) = 0
  ring

theorem full_candidate_prf_initial_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 16) :
    actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
      (fullTypedSourceCandidate statement witness) (prfInitialAttempt lane.val) = 0 := by
  by_cases rate : lane.val < 4
  · rw [prfInitialAttempt, if_pos rate]
    exact full_candidate_prf_rate_zero statement witness valid ⟨lane.val, rate⟩
  · rw [prfInitialAttempt, if_neg rate, actual_prf_padding_residual,
      full_candidate_prf_initial_field statement witness valid lane, if_neg rate, sub_self]

theorem full_candidate_actual_prf_all_16_zero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 16) :
    ∃ entry, exactCsrAttempts[15789 + lane.val]? = some entry ∧ entry.family = 10 ∧
      entry.localIndex = lane.val ∧
      actualCsrResidual (fun index => ((encodePublicStatement statement).getD index 0 : F))
        (fullTypedSourceCandidate statement witness) entry = 0 := by
  refine ⟨prfInitialAttempt lane.val, exact_prf_initial_lookup lane, ?_, ?_,
    full_candidate_prf_initial_zero statement witness valid lane⟩
  all_goals unfold prfInitialAttempt; split <;> rfl

end
end HegemonCrypto.SmallWood.V8Smz9SourcePrfInitial
