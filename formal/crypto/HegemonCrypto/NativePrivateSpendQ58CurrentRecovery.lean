/- Draft private-spend degree-13172 finite recovery instantiation.
Current COMPFF01 degree successor. Kernel check pending; no QROM endpoint asserted. -/
import HegemonCrypto.NativePrivateSpendQ58CurrentGeometry
import HegemonCrypto.NativeHtlcUniversalMatrix

/-!
# Native HTLC q58 calculated-decoder endpoint

The theorem here is conditional on the parser/source-table binding stated in
its signature. It proves an actual 13173-point interpolation result or one of
the two explicit bad events. It does not extract a table from a quantum Merkle
commitment, prove the new line-count premise, or assert Rust verifier refinement.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRecovery

open Polynomial
open V8Smz9McaRecovery V8Smz9McaDecoder NativeHtlcUniversalMatrix
open scoped BigOperators
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 0
set_option maxHeartbeats 0

abbrev Position := Fin 8388608
abbrev MaskRow := Fin 5
abbrev DataRow := Fin 140
abbrev Coefficients (F : Type*) := DataRow → MaskRow → F

variable {F : Type*} [Field F] [Fintype F]

/-- This is the outstanding response-universal counting proposition, not an axiom.
It quantifies over every source direction and every prior matrix. -/
def LineCountPremise (point : Position → F) : Prop :=
  ∀ (prior : MaskRow → Position → F) (direction : Position → F),
    (badLineLabels point 13172 360448 prior direction).card ≤ 16445033384594

theorem matrix_card_bound_of_line_count
    (point : Position → F) (lineCount : LineCountPremise point)
    (data : ℕ → Position → F) (masks : MaskRow → Position → F) :
    (badMatrices point 13172 360448 data masks 140).card *
        Fintype.card (MaskRow → F) ≤
      Fintype.card (Coefficients F) * (140 * 16445033384594) := by
  have bound := universal_bad_matrix_card_bound point 13172 360448 data masks
    140 16445033384594 (fun _ prior => lineCount prior _)
  simpa only [Coefficients, DataRow, MaskRow,
    Fintype.card_fun, Fintype.card_fin] using bound

/-- The response selector is fixed before the query and may depend arbitrarily
on the matrix. The complete supplied source table is likewise fixed before the
matrix. No independence of the response from the matrix is assumed. -/
structure SourceResponseView (F : Type*) [Field F] [Fintype F] where
  data : ℕ → Position → F
  masks : MaskRow → Position → F
  response : Coefficients F → BoundedResponse F MaskRow 13172
  coefficients : Coefficients F

def support (point : Position → F) (v : SourceResponseView F) : Finset Position :=
  responseSupport point 13172 v.data v.masks v.response v.coefficients

def decoded (point : Position → F) (v : SourceResponseView F) :
    Option (DecodedSource F MaskRow 140) :=
  responseDecoder point 13172 v.data v.masks v.response v.coefficients

def WholeResponseRecovered (point : Position → F) (v : SourceResponseView F) : Prop :=
  ∃ candidate : DecodedSource F MaskRow 140,
    decoded point v = some candidate ∧
    (interpolationNodes 13172 (support point v)).card = 13173 ∧
    CandidateAgrees point (support point v) v.data v.masks candidate ∧
    (∀ row, (candidate.masks row).natDegree ≤ 13172) ∧
    (∀ column, (candidate.data column).natDegree ≤ 13172) ∧
    ∀ row, responsePolynomials (v.response v.coefficients) row =
      projectedSource candidate v.coefficients row

/-- This endpoint makes the accepted-wire bridge explicit. Instantiate `Wire`
with the possible final-query continuations of one fixed prior execution.
Every accepted continuation must have the same complete source, response
selector and matrix coefficients; only its final query may vary. The caller
still must establish that the immutable proof bytes and prior oracle execution
induce `observed`, and that its accepted query has the stated binding. This
pointwise theorem itself asserts no probability or quantum extraction bound. -/
theorem accepted_execution_decoder_endpoint
    {Wire : Type*} (accepted : Wire → Prop)
    (observed : Wire → SourceResponseView F)
    (view : SourceResponseView F)
    (query : Wire → QuerySample Position 58)
    (point : Position → F) (injective : Function.Injective point)
    (sourceResponseWholeViewBinding :
      ∀ wire, accepted wire → observed wire = view)
    (acceptedQueryBinding : ∀ wire, accepted wire →
      (query wire).val ⊆ support point (observed wire))
    (wire : Wire) (accepts : accepted wire) :
    WholeResponseRecovered point view ∨
      BadMatrix point 13172 360448 view.data view.masks
        view.coefficients ∨
      ((support point view).card < 360448 ∧
        (query wire).val ⊆ support point view) := by
  classical
  have acceptedSample := acceptedQueryBinding wire accepts
  rw [sourceResponseWholeViewBinding wire accepts] at acceptedSample
  cases hdecode : decoded point view with
  | some candidate =>
      left
      have hdecoded : responseDecoder point 13172
          view.data view.masks view.response
          view.coefficients = some candidate := hdecode
      have recovered := decoded_source_agrees_and_has_bounded_degree
        point injective 13172 (support point view)
        view.data view.masks candidate hdecoded
      refine ⟨candidate, hdecode, ?_, recovered.2.1,
        recovered.2.2.1, recovered.2.2.2, ?_⟩
      · exact interpolation_nodes_card 13172 _ recovered.1
      · intro row
        exact decoded_response_equals_projection point injective 13172
          view.data view.masks view.response
          view.coefficients candidate hdecoded row
  | none =>
      right
      have failure : query wire ∈
          decoderFailureEvent point 13172 58
            view.data view.masks view.response
            view.coefficients := by
        simp only [decoderFailureEvent, Finset.mem_filter,
          Finset.mem_univ, true_and]
        exact ⟨acceptedSample, hdecode⟩
      exact accepted_decoder_failure_implies_bad_matrix_or_small_support
        point injective 13172 360448 58 (by decide)
        view.data view.masks view.response
        view.coefficients (query wire) failure

/-- Outside the matrix event every failed accepted sample lies in the one
pre-query full support, giving the exact without-replacement sample count. -/
theorem nonexceptional_q58_failure_card
    (point : Position → F) (injective : Function.Injective point)
    (v : SourceResponseView F)
    (notBad : ¬ BadMatrix point 13172 360448 v.data v.masks v.coefficients) :
    (decoderFailureEvent point 13172 58 v.data v.masks
      v.response v.coefficients).card ≤ Nat.choose 360447 58 := by
  exact nonexceptional_decoder_failure_card_bound point injective
    13172 360448 58 (by decide) v.data v.masks v.response v.coefficients notBad

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRecovery
