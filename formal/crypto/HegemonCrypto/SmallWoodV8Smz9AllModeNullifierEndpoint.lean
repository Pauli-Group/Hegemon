import HegemonCrypto.SmallWoodV8Smz9SingleAuthorizationEndpoint
import HegemonCrypto.SmallWoodV8Smz9NonSingleAuthorizationLinks

namespace HegemonCrypto.SmallWood.V8Smz9AllModeNullifierEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex)
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SingleAuthorizationEndpoint
open HegemonCrypto.SmallWood.V8Smz9NonSingleAuthorizationLinks
open HegemonCrypto.SmallWood.V8Smz9NullifierSource

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem admitted_input_effective_prf {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {input : Nat} (bound : input < inputCount) (active : flagAt statement.inputFlags input = 1) :
    packedWord packed (rawIndex (95 + input)) = effectiveInputAuthorizationPrf
      exactV8SemanticPrimitives (projectTypedWitness statement packed) input := by
  cases mode : projectAuthorizationMode packed with
  | singleKey => exact admitted_single_input_effective_prf domain mode bound active
  | approvalStep => exact admitted_approval_input_effective_prf domain mode bound active
  | finalThresholdSpend => exact admitted_final_input_effective_prf domain mode bound active

theorem admitted_packed_project_typed_nullifiers {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    ∀ input, input < inputCount → flagAt statement.inputFlags input = 1 →
      exactV8SemanticPrimitives.nullifier input
        (effectiveInputAuthorizationPrf exactV8SemanticPrimitives (projectTypedWitness statement packed) input)
        ((projectTypedWitness statement packed).inputs.getD input default).position
        ((projectTypedWitness statement packed).inputs.getD input default).note.rho =
          digestAt statement.nullifiers input := by
  intro input bound active
  have source := admitted_packed_project_typed_nullifiers_raw_scalar domain input bound active
  rw [admitted_input_effective_prf domain bound active] at source
  exact source


end HegemonCrypto.SmallWood.V8Smz9AllModeNullifierEndpoint
