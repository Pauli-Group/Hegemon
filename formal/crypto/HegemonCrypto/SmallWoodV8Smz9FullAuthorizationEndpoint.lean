import HegemonCrypto.SmallWoodV8Smz9SingleAuthorizationEndpoint
import HegemonCrypto.SmallWoodV8Smz9NonSingleAuthorizationLinks
import HegemonCrypto.SmallWoodV8Smz9AuthorizationHashBindings
import HegemonCrypto.SmallWoodV8Smz9AuthorizationCanonicalEndpoint
import HegemonCrypto.SmallWoodV8Smz9AuthorizationNextCanonical
import HegemonCrypto.SmallWoodV8Smz9AuthorizationFinalThreshold
import HegemonCrypto.SmallWoodV8Smz9PolicySourceWords
import HegemonCrypto.SmallWoodV8Smz9ActionIntentSourceWords
import HegemonCrypto.SmallWoodV8Smz9AllModeNullifierEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9FullAuthorizationEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex)
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9SingleAuthorizationEndpoint
open HegemonCrypto.SmallWood.V8Smz9NonSingleAuthorizationLinks
open HegemonCrypto.SmallWood.V8Smz9AuthorizationHashBindings
open HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonicalEndpoint
open HegemonCrypto.SmallWood.V8Smz9AuthorizationNextCanonical
open HegemonCrypto.SmallWood.V8Smz9AuthorizationFinalThreshold
open HegemonCrypto.SmallWood.V8Smz9PolicySourceWords
open HegemonCrypto.SmallWood.V8Smz9ActionIntentSourceWords
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrfLegacy
open HegemonCrypto.SmallWood.V8Smz9NullifierSource

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem admitted_packed_project_typed_approval_authorization {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    V8AuthorizationValid exactV8SemanticPrimitives statement (projectTypedWitness statement packed) := by
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by simp only [mode]; decide
  have activity := admitted_approval_activity domain mode
  have canonical := accepted_non_single_canonical_authorization domain.2.2 notSingle
  have shared := accepted_approval_shared_opening_fields domain.2.2 mode
  have bitmap := accepted_approval_bitmap_transition domain.2.2 mode
  have firstActive : flagAt statement.inputFlags 0 = 1 := by simp [activity.1, flagAt]
  have secondActive : flagAt statement.inputFlags 1 = 1 := by simp [activity.1, flagAt]
  have policy := (accepted_non_single_current_policy_hash domain.2.2 notSingle).trans
    (accepted_policy_digest_eq_exact domain.2.2)
  have firstKey := admitted_approval_input_key domain mode (by decide : 0 < 2) firstActive
  have secondKey := admitted_approval_input_key domain mode (by decide : 1 < 2) secondActive
  unfold V8AuthorizationValid
  dsimp only
  rw [show (projectTypedWitness statement packed).authorization.mode = .approvalStep from mode]
  refine ⟨activity.1, activity.2, canonical.1,
    accepted_approval_canonical_next_accumulator domain.2.2 mode,
    canonical.2, policy, shared.1, shared.2.1, shared.2.2.1, shared.2.2.2,
    accepted_approval_count_increment domain.2.2 mode, bitmap.1, bitmap.2,
    admitted_approval_signer_bound domain mode, ?_, ?_, admitted_approval_output_zero_key domain mode⟩
  · simpa only [if_true, exactV8SemanticPrimitives, projectTypedWitness] using firstKey
  · rw [selected_project_transaction_spend_key statement packed (by decide : 0 < 2) firstActive]
    simpa only [Nat.one_ne_zero, if_false, exactV8SemanticPrimitives, projectTypedWitness] using secondKey

theorem admitted_packed_project_typed_final_authorization {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend) :
    V8AuthorizationValid exactV8SemanticPrimitives statement (projectTypedWitness statement packed) := by
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by simp only [mode]; decide
  have activity := admitted_final_activity domain mode
  have canonical := accepted_non_single_canonical_authorization domain.2.2 notSingle
  have firstActive : flagAt statement.inputFlags 0 = 1 := by simp [activity, flagAt]
  have secondActive : flagAt statement.inputFlags 1 = 1 := by simp [activity, flagAt]
  have policy := (accepted_non_single_current_policy_hash domain.2.2 notSingle).trans
    (accepted_policy_digest_eq_exact domain.2.2)
  have intent := (accepted_final_current_intent_hash domain.2.2 mode).trans
    (admitted_action_intent_digest_eq_exact domain)
  have firstKey := admitted_final_input_key domain mode (by decide : 0 < 2) firstActive
  have secondKey := admitted_final_input_key domain mode (by decide : 1 < 2) secondActive
  unfold V8AuthorizationValid
  dsimp only
  rw [show (projectTypedWitness statement packed).authorization.mode = .finalThresholdSpend from mode]
  refine ⟨activity, canonical.1, accepted_final_next_accumulator_zero domain.2.2 mode,
    canonical.2, policy, accepted_final_approval_count_ge_threshold domain.2.2 mode,
    intent, ?_, ?_⟩
  · simpa only [if_true, exactV8SemanticPrimitives, projectTypedWitness] using firstKey
  · simpa only [Nat.one_ne_zero, if_false, exactV8SemanticPrimitives, projectTypedWitness] using secondKey

/-- The actual accepted mode selects a complete source-derived authorization
proof; no authorization relation is assumed as an endpoint premise. -/
theorem admitted_packed_project_typed_authorization {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    V8AuthorizationValid exactV8SemanticPrimitives statement (projectTypedWitness statement packed) := by
  cases mode : projectAuthorizationMode packed with
  | singleKey => exact admitted_packed_project_typed_single_authorization domain mode
  | approvalStep => exact admitted_packed_project_typed_approval_authorization domain mode
  | finalThresholdSpend => exact admitted_packed_project_typed_final_authorization domain mode


end HegemonCrypto.SmallWood.V8Smz9FullAuthorizationEndpoint
