import HegemonCrypto.SmallWoodV8Smz9CryptographicLinksEndpoint
import HegemonCrypto.SmallWoodV8Smz9StableEnabledEndpoint
import HegemonCrypto.SmallWoodV8Smz9SemanticBalance

namespace HegemonCrypto.SmallWood.V8Smz9ExactSemanticEndpoint

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticBalance
open HegemonCrypto.SmallWood.V8Smz9SemanticStableEnabledEndpoint

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

/-- Complete fixed V8 relation semantics for the actual typed source
projection. Its premise is public canonical admission plus arbitrary packed
program acceptance, never the semantic conclusion or an honest-lowering
certificate. Executable byte/frontend refinement is a separate obligation. -/
theorem admitted_packed_project_typed_exact_semantics {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    ExactV8RelationSemanticValid statement (projectTypedWitness statement packed) := by
  exact ⟨domain.2.1, admitted_packed_project_typed_witness_canonical domain,
    admitted_packed_project_typed_cryptographic_links domain,
    admitted_packed_project_typed_witness_balance domain,
    admitted_stable_transition domain⟩

/-- Full-action semantics additionally require the caller's actual consensus
context and inline-ciphertext admission predicates.  The private relation
conclusion is proved above, not supplied as a premise of this wrapper. -/
theorem admitted_packed_project_typed_exact_full_action
    {context : V8StablecoinContext} {ciphertexts : V8InlineCiphertexts}
    {statement : V8PublicStatement} {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (contextMatches : ConsensusContextMatches context statement)
    (ciphertextsMatch : InlineCiphertextsMatch exactV8SemanticPrimitives statement ciphertexts) :
    ExactV8FullActionSemanticValid context ciphertexts statement
      (projectTypedWitness statement packed) := by
  exact ⟨admitted_packed_project_typed_exact_semantics domain, contextMatches, ciphertextsMatch⟩


end HegemonCrypto.SmallWood.V8Smz9ExactSemanticEndpoint
