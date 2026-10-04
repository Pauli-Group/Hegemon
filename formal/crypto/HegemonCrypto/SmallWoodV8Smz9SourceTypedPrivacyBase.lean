import HegemonCrypto.SmallWoodV8Smz9CurrentPublicContext
import HegemonCrypto.SmallWoodV8Smz9SourcePublicErasure

/-! Public-only row accounting and reflexive source-control-flow erasure.
These facts require neither packed acceptance nor a typed witness. -/

namespace HegemonCrypto.SmallWood.V8Smz9TypedSourcePrivacy

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9CurrentPublicContext V8Smz9SourceLifetime V8Smz9SourcePublicErasure
open scoped Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

private theorem retained_bound_from_samples (rows : Nat)
    (total : 5 * max 830 rows ≤ 103025) : rows ≤ 20605 := by
  omega

/-- The retained source count is derived from public specialization. -/
theorem typed_retained_rows_bound (statement : V8PublicStatement) :
    (retainedAttempts (encodePublicStatement statement)).length ≤ 20605 := by
  exact retained_bound_from_samples _ (batching_sample_count_le (encodePublicStatement statement))

variable {bound : Nat} {Work : Type} [Fintype Work]

/-- Every constructor and every possible answer branch preserves self-erasure. -/
theorem source_lifetime_publicly_equivalent_self {queries requests : Nat}
    (lifetime : Lifetime bound Work queries requests) : PubliclyEquivalent lifetime lifetime := by
  induction lifetime with
  | finish event => exact PubliclyEquivalent.finish event
  | gate operation next ih => exact PubliclyEquivalent.gate operation ih
  | quantumQuery next ih => exact PubliclyEquivalent.quantumQuery ih
  | honestRead input next ih => exact PubliclyEquivalent.honestRead input ih
  | instrument operation next ih => exact PubliclyEquivalent.instrument operation ih
  | random source next ih => exact PubliclyEquivalent.random source ih
  | sourceRequest request next ih => exact PubliclyEquivalent.sourceRequest request request rfl ih


end
end HegemonCrypto.SmallWood.V8Smz9TypedSourcePrivacy
