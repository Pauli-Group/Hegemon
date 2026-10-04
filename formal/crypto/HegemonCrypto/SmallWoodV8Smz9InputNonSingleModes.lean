import HegemonCrypto.SmallWoodV8Smz9InputAuthorizationModes

namespace HegemonCrypto.SmallWood.V8Smz9InputNonSingleModes

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointInputModes

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

theorem accepted_approval_mode_words {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    authorizationWord packed 0 = 0 ∧ authorizationWord packed 1 = 1 ∧
      authorizationWord packed 2 = 0 := by
  have approval := accepted_approval_mode_word accepted mode
  rcases accepted_authorization_one_hot accepted with first | second | third
  · omega
  · exact second
  · omega

theorem accepted_final_mode_words {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) :
    authorizationWord packed 0 = 0 ∧ authorizationWord packed 1 = 0 ∧
      authorizationWord packed 2 = 1 := by
  have finalMode := accepted_final_mode_word accepted mode
  rcases accepted_authorization_one_hot accepted with first | second | third
  · omega
  · omega
  · exact third

theorem accepted_active_approval_input_authorization_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    (input : Fin 2) (word : Fin 5) (active : publicWords.getD input.val 0 = 1) :
    authorizationRawWord packed (inputAuthOutRow input.val word.val) =
      authorizationRawWord packed (inputAuthApprovalRow input.val word.val) := by
  have equality := accepted_input_authorization_mode_field accepted input word
  obtain ⟨single, approval, finalMode⟩ := accepted_approval_mode_words accepted mode
  simp only [active, single, approval, finalMode, Nat.cast_one, Nat.cast_zero,
    one_mul, zero_mul, add_zero, zero_add] at equality
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) equality

theorem accepted_active_final_input_authorization_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend)
    (input : Fin 2) (word : Fin 5) (active : publicWords.getD input.val 0 = 1) :
    authorizationRawWord packed (inputAuthOutRow input.val word.val) =
      authorizationRawWord packed (inputAuthFinalRow input.val word.val) := by
  have equality := accepted_input_authorization_mode_field accepted input word
  obtain ⟨single, approval, finalMode⟩ := accepted_final_mode_words accepted mode
  simp only [active, single, approval, finalMode, Nat.cast_one, Nat.cast_zero,
    one_mul, zero_mul, zero_add] at equality
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) equality


end HegemonCrypto.SmallWood.V8Smz9InputNonSingleModes
