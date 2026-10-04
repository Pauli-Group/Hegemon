import HegemonCrypto.SmallWoodV8Smz9InputAuthorizationModes
import HegemonCrypto.SmallWoodV8Smz9InputAuthorizationKeys
import HegemonCrypto.SmallWoodV8Smz9PrfLegacyBinding
import HegemonCrypto.SmallWoodV8Smz9NullifierSource

namespace HegemonCrypto.SmallWood.V8Smz9SingleAuthorizationEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex)
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointInputModes
open HegemonCrypto.SmallWood.V8Smz9InputAuthorizationKeys
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrfLegacy

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

theorem admitted_single_input_authorization_key {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input = 1) :
    ((projectTypedWitness statement packed).inputs.getD input default).note.authorizationKey =
      ((exactV8TransactionPrf (prfWords packed)).drop 1).take 4 := by
  rw [accepted_typed_input_authorization_source domain.2.2 statement ⟨input, bound⟩]
  rw [← accepted_legacy_key_eq_exact_prf domain.2.2]
  apply List.map_congr_left
  intro limb member
  have limbBound := List.mem_range.mp member
  have rawActive : publicWords.getD input 0 = 1 :=
    (admitted_public_input_flag domain bound).trans active
  have equation := accepted_active_single_input_authorization_word domain.2.2 mode
    ⟨input, bound⟩ ⟨1 + limb, by omega⟩ rawActive
  have nonzero : 1 + limb ≠ 0 := by omega
  have outputRow : 96 + 4 * input + (1 + limb) = 97 + 4 * input + limb := by omega
  have legacyRow : 105 + (1 + limb) = 106 + limb := by omega
  simp only [inputAuthOutRow, nonzero, if_false, outputRow, legacyRow] at equation
  simpa only [authorizationRawWord, rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using equation

/-- Complete single-key authorization, including actual transaction-PRF key binding. -/
theorem admitted_packed_project_typed_single_authorization {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey) :
    V8AuthorizationValid exactV8SemanticPrimitives statement (projectTypedWitness statement packed) := by
  have zeroShape := accepted_single_authorization_zero_shape domain.2.2 mode
  unfold V8AuthorizationValid
  dsimp only
  rw [show (projectTypedWitness statement packed).authorization.mode = .singleKey from mode]
  refine ⟨zeroShape.1, zeroShape.2.1, zeroShape.2.2, ?_⟩
  intro input bound active
  rw [selected_project_transaction_spend_key statement packed bound active]
  exact admitted_single_input_authorization_key domain mode bound active

/-- Single-key nullifier scalar is the actual exact transaction-PRF limb zero. -/
theorem admitted_single_input_effective_prf {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .singleKey)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input = 1) :
    packedWord packed (rawIndex (95 + input)) = effectiveInputAuthorizationPrf
      exactV8SemanticPrimitives (projectTypedWitness statement packed) input := by
  have rawActive : publicWords.getD input 0 = 1 :=
    (admitted_public_input_flag domain bound).trans active
  have source := accepted_active_single_input_authorization_word domain.2.2 mode
    ⟨input, bound⟩ ⟨0, by decide⟩ rawActive
  have exactPrf := accepted_legacy_word_eq_exact_prf domain.2.2 ⟨0, by decide⟩
  have result : packedWord packed (rawIndex (95 + input)) =
      (exactV8TransactionPrf (prfWords packed)).getD 0 0 := by
    simpa only [inputAuthOutRow, if_true, Nat.add_zero, authorizationRawWord, rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add] using
      source.trans exactPrf
  unfold effectiveInputAuthorizationPrf
  dsimp only
  rw [show (projectTypedWitness statement packed).authorization.mode = .singleKey from mode]
  rw [project_typed_input_at statement packed default bound]
  simpa only [projectInput, active, Nat.one_ne_zero, if_false, exactV8SemanticPrimitives,
    prfWords, wordAt] using result


end HegemonCrypto.SmallWood.V8Smz9SingleAuthorizationEndpoint
