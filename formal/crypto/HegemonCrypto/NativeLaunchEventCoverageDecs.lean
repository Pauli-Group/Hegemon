import HegemonCrypto.NativeLaunchRelationModelResponse

/-!
# Same-branch native DECS decoder event cover

The query-support condition is proved from literal response restoration and
coordinate readback; it is not an accepted-query assumption. The remaining
full-response FPP binding and authenticated source-cell equalities are exposed
as exact equations. This covers failed source decoding only: it does not prove
that an accepted false RP06/HTLC relation forces this failure. That implication
needs the current-family PIOP and relation refinement, and is not asserted here.
-/
namespace HegemonCrypto.SmallWood.NativeLaunchEventCoverageDecs

open NativeLaunchRelationModelResponse
open V8Smz9McaRecovery V8Smz9McaDecoder NativeHtlcUniversalMatrix

set_option autoImplicit false
noncomputable section

variable {Position : Type*} [Fintype Position] [LinearOrder Position]

/-- The unordered q38/q58 sample is computed from the typed ordered query.
Distinct verifier points imply distinct positions, so there is no supplied
sample-cardinality certificate. -/
def wireQuery {branch : Branch} (point : Position → Goldilocks)
    (wire : WireFields branch Position)
    (distinct : Function.Injective (fun index => point (wire.positions index))) :
    QuerySample Position (queryCount branch) := by
  classical
  refine ⟨Finset.univ.image wire.positions, ?_⟩
  have positionInjective : Function.Injective wire.positions := by
    intro a b same
    exact distinct (congrArg point same)
  rw [Finset.card_image_of_injective _ positionInjective,
    Finset.card_univ, Fintype.card_fin]

/-- Derived support inclusion from the actual calculated restore output. -/
theorem calculated_wire_query_within_response_support
    {branch : Branch} (point : Position → Goldilocks)
    (wire : WireFields branch Position) (matrix : Matrix)
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks)
    (response : Matrix → BoundedResponse Goldilocks MaskRow (degree branch))
    (distinct : Function.Injective (fun index => point (wire.positions index)))
    (readback : SourceReadback wire data masks)
    (fppBinding : response matrix = calculatedResponse point wire matrix) :
    (wireQuery point wire distinct).val ⊆
      responseSupport point (degree branch) data masks response matrix := by
  intro position member
  obtain ⟨index, _, equal⟩ := Finset.mem_image.mp member
  subst position
  exact query_agrees_with_prior_response point wire matrix data masks response
    distinct readback fppBinding index

/-- A failed calculated decoder on this branch lies in either its universal
matrix event or its later small-support query event. The same matrix, source
view, response rule and query occur on both sides. -/
theorem same_branch_failed_decoder_event_cover
    {branch : Branch} (point : Position → Goldilocks)
    (injective : Function.Injective point)
    (wire : WireFields branch Position) (matrix : Matrix)
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks)
    (response : Matrix → BoundedResponse Goldilocks MaskRow (degree branch))
    (distinct : Function.Injective (fun index => point (wire.positions index)))
    (readback : SourceReadback wire data masks)
    (fppBinding : response matrix = calculatedResponse point wire matrix)
    (threshold : Nat) (thresholdValid : degree branch < threshold)
    (failed : responseDecoder point (degree branch) data masks response matrix = none) :
    BadMatrix point (degree branch) threshold data masks matrix ∨
      ((responseSupport point (degree branch) data masks response matrix).card < threshold ∧
        (wireQuery point wire distinct).val ⊆
          responseSupport point (degree branch) data masks response matrix) := by
  have within := calculated_wire_query_within_response_support point wire matrix
    data masks response distinct readback fppBinding
  have event : wireQuery point wire distinct ∈
      decoderFailureEvent point (degree branch) (queryCount branch)
        data masks response matrix := by
    classical
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _, within, failed⟩
  exact accepted_decoder_failure_implies_bad_matrix_or_small_support point injective
    (degree branch) threshold (queryCount branch) thresholdValid data masks response matrix
    (wireQuery point wire distinct) event

/-- Successful decoding uses the library's calculated interpolation candidate.
It recovers the complete restored response polynomial on this branch; the
candidate is not furnished by the prover or chosen using the final query. -/
theorem same_branch_calculated_candidate_recovers_complete_response
    {branch : Branch} (point : Position → Goldilocks)
    (injective : Function.Injective point)
    (wire : WireFields branch Position) (matrix : Matrix)
    (data : Nat → Position → Goldilocks) (masks : MaskRow → Position → Goldilocks)
    (response : Matrix → BoundedResponse Goldilocks MaskRow (degree branch))
    (fppBinding : response matrix = calculatedResponse point wire matrix)
    (candidate : DecodedSource Goldilocks MaskRow 140)
    (decoded : responseDecoder point (degree branch) data masks response matrix = some candidate)
    (row : MaskRow) :
    (responsePolynomials (calculatedResponse point wire matrix) row) =
      projectedSource candidate matrix row := by
  rw [← fppBinding]
  exact decoded_response_equals_projection point injective (degree branch)
    data masks response matrix candidate decoded row

end
end HegemonCrypto.SmallWood.NativeLaunchEventCoverageDecs
