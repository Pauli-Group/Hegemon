import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerInactive
import HegemonCrypto.SmallWoodV8Smz9AuthorizationSignerDistinct

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical
open HegemonCrypto.SmallWood.V8Smz9AuthorizationRoleNonzero

theorem accepted_non_single_canonical_signer_tags {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    CanonicalSignerTags (projectAuthorization packed) := by
  have shape := accepted_signer_tags_exact_shape accepted
  refine ⟨shape.1, shape.2, ?_, ?_⟩
  · intro slot active
    exact accepted_active_signer_tag_nonzero accepted mode active
  · constructor
    · intro left right ordered rightActive
      exact accepted_active_signer_first_words_distinct accepted mode ordered rightActive
    · intro slot inactive bound
      exact accepted_inactive_signer_tag_zero accepted mode inactive bound


end HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints
