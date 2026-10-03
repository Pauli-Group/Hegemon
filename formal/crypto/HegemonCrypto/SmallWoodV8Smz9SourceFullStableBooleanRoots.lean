import HegemonCrypto.SmallWoodV8Smz9SourceStableBooleanRoots
import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate

/-! The concrete full candidate satisfies the generated Boolean and radix-four
stable roots. This does not claim the multiplication, selector, inverse, CSR or
other remaining roots, and does not infer packed acceptance. -/

namespace HegemonCrypto.SmallWood.V8Smz9SourceStableBooleanRoots

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SourceTypedPrefix
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (fieldAt)
open HegemonCrypto.SmallWood.V8Smz9SemanticCryptographicLinks (laneField)

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

noncomputable section

theorem full_candidate_lane_field_as_source_tail (statement : V8PublicStatement)
    (witness : V8Witness) (lane : Fin 64) :
    laneField (fullTypedSourceCandidate statement witness) lane.val =
      sourceTailLaneField (typedPrefix statement witness) statement witness
        (typedSourceFinals statement witness) lane := by
  funext row
  rw [full_candidate_as_tail_embedding]
  rfl

theorem full_candidate_actual_stable_boolean_root_zero (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness) (lane : Fin 64) :
    fieldAt exactNonlinearExpressions
      (fun index => ((encodePublicStatement statement).getD index 0 : F))
      (laneField (fullTypedSourceCandidate statement witness) lane.val) 8130 = 0 := by
  rw [full_candidate_lane_field_as_source_tail]
  exact valid_source_tail_actual_boolean_root_zero (typedPrefix statement witness) statement witness valid
      (typedSourceFinals statement witness) (typed_prefix_length statement witness) _ lane

/-- Low radix-digit roots hold for the actual constructor even before typed admission. -/
theorem full_candidate_actual_stable_radix_root_zero (statement : V8PublicStatement)
    (witness : V8Witness) (lane : Fin 64) (slot : Fin 23) :
    fieldAt exactNonlinearExpressions
      (fun index => ((encodePublicStatement statement).getD index 0 : F))
      (laneField (fullTypedSourceCandidate statement witness) lane.val) (8138 + 6 * slot.val) = 0 := by
  rw [full_candidate_lane_field_as_source_tail]
  exact source_tail_actual_radix_root_zero (typedPrefix statement witness) statement witness
      (typedSourceFinals statement witness) (typed_prefix_length statement witness) _ lane slot

/-- Exact generated root-list indices: 24 roots across all 64 lanes.
The only data premise is the fixed `ExactV8RelationSemanticValid` relation. -/
theorem full_candidate_actual_stable_boolean_and_radix_roots_zero (statement : V8PublicStatement)
    (witness : V8Witness) (valid : ExactV8RelationSemanticValid statement witness) :
    ∀ lane : Fin 64,
      (exactNonlinearRoots[805]?).map
        (fieldAt exactNonlinearExpressions
          (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 ∧
      ∀ slot : Fin 23, (exactNonlinearRoots[807 + slot.val]?).map
        (fieldAt exactNonlinearExpressions
          (fun index => ((encodePublicStatement statement).getD index 0 : F))
          (laneField (fullTypedSourceCandidate statement witness) lane.val)) = some 0 := by
  intro lane
  constructor
  · rw [actual_stable_boolean_root_identity.1,Option.map_some,
      full_candidate_actual_stable_boolean_root_zero statement witness valid lane]
  · intro slot
    rw [(actual_stable_radix_root_identities slot).1,Option.map_some,
      full_candidate_actual_stable_radix_root_zero statement witness lane slot]


end
end HegemonCrypto.SmallWood.V8Smz9SourceStableBooleanRoots
