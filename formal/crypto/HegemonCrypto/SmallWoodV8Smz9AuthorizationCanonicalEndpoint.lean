import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerConstraints

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonicalEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical
open HegemonCrypto.SmallWood.V8Smz9AuthorizationOrderTail
open HegemonCrypto.SmallWood.V8Smz9AuthorizationRoleNonzero
open HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem accepted_non_single_canonical_current_accumulator {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    CanonicalAccumulator (projectAuthorization packed).current := by
  have shape := accepted_non_single_current_shape accepted mode
  exact ⟨shape.1,
    accepted_non_single_policy_root_nonzero accepted mode,
    shape.2.1,
    accepted_non_single_intent_digest_nonzero accepted mode,
    shape.2.2.1,
    accepted_threshold_le_signer_count accepted mode,
    shape.2.2.2.1,
    accepted_current_approval_count_le_signer accepted mode,
    shape.2.2.2.2.2.1,
    shape.2.2.2.2.2.2.1,
    shape.2.2.2.2.2.2.2,
    (by
      intro slot inactive bound
      exact accepted_current_bitmap_inactive_zero accepted mode inactive bound)⟩

theorem accepted_non_single_canonical_authorization {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    CanonicalAccumulator (projectAuthorization packed).current ∧
      CanonicalSignerTags (projectAuthorization packed) :=
  ⟨accepted_non_single_canonical_current_accumulator accepted mode,
    accepted_non_single_canonical_signer_tags accepted mode⟩


end HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonicalEndpoint
