import HegemonCrypto.SmallWoodV8Smz9FullAuthorizationEndpoint
import HegemonCrypto.SmallWoodV8Smz9InputMerklePublic
import HegemonCrypto.SmallWoodV8Smz9SemanticEndpointOutputs

namespace HegemonCrypto.SmallWood.V8Smz9ExactSemanticEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9FullAuthorizationEndpoint
open HegemonCrypto.SmallWood.V8Smz9AllModeNullifierEndpoint
open HegemonCrypto.SmallWood.V8Smz9InputMerklePublic
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointOutputs

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem admitted_packed_project_typed_cryptographic_links {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    V8CryptographicLinksValid exactV8SemanticPrimitives statement
      (projectTypedWitness statement packed) := by
  refine ⟨?_, admitted_packed_project_typed_output_commitments domain,
    admitted_packed_project_typed_authorization domain⟩
  intro input bound active
  exact ⟨admitted_packed_project_typed_merkle_roots domain input bound active,
    admitted_packed_project_typed_nullifiers domain input bound active⟩


end HegemonCrypto.SmallWood.V8Smz9ExactSemanticEndpoint
