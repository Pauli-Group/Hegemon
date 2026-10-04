import SmzaRp05CurrentMaxAgreementRecovery
import SmzaRp05CurrentQueryEventCore

/-! The current maximum-agreement decoder, rather than an independently
chosen interpolation support, supplies the rows in the twelve-check event.
The table-to-leaf binding remains explicit for the physical record join.
No claim about the distribution of a post-query-selected table is made. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentRecoveredQueryBridge

open HegemonCrypto.SmallWood
open SmzaRp05CurrentMaxAgreementRecovery
open SmzaRp05CurrentQueryEventCore
open SmzaRp05CurrentTwelveCalculated
open SmzaRp05CurrentQ38DetectionProbability
open SmzaRp05GlobalOpeningReadback
open HegemonCrypto.SmallWood.V8Smz9McaDecoder
  (responseDecoder responseSupport DecodedSource)

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
noncomputable section

attribute [local irreducible]
  HegemonCrypto.SmallWood.V8Smz9McaRecovery.querySampleFintype

private theorem exact_combinations_of_no_discrepancy
    (rows : SmzaQ38Recovery.RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials)
    (none : ¬ ∃ combination,
      SmzaQ38LvcsOpening.discrepancy rows points claimed combination ≠ 0) :
    ∀ combination, claimed combination =
      SmzaQ38LvcsOpening.rowCombination rows points combination := by
  intro combination
  have zero : SmzaQ38LvcsOpening.discrepancy rows points claimed combination = 0 := by
    by_contra nonzero
    exact none ⟨combination, nonzero⟩
  exact sub_eq_zero.mp zero

/-- Actual decoder success and accepted MCA support derive the precise row
agreement needed by current-map LVCS detection. No arbitrary recovered-row
agreement or 406-node support is a premise. -/
theorem recovered_rows_match_authenticated_query
    {ns : SmzaRp05LeafNamespace.Namespace}
    {records : SmzaRp05FilteredDecoderInstability.RawRecords}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients)
    (candidate : DecodedSource Goldilocks (Fin 5) 140)
    (decoded : responseDecoder SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint
      405 data masks response coefficients = some candidate)
    (accepted : query.val ⊆ responseSupport
      SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405 data masks response coefficients)
    (dataBinding : ∀ column : Fin 140, ∀ index, index ∈ query.val →
      data column.val index = SmzaQ38OracleExtraction.committedColumnValue
        (authenticatedReadbackOracle claims) column index) :
    ∀ column index, index ∈ query.val →
      (candidate.data column).eval (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) =
        SmzaQ38OracleExtraction.committedColumnValue
          (authenticatedReadbackOracle claims) column index := by
  intro column index member
  exact (decoded_source_agrees_on_accepted_query data masks response coefficients
    candidate query decoded accepted column index member).trans
      (dataBinding column index member)

/-- Once the actual current decoder succeeds, either the sampled query is
in the bounded current LVCS miss event or all twelve source claim polynomials
equal the corresponding combinations of the recovered rows. -/
theorem recovered_current_checks_bad_or_exact
    {ns : SmzaRp05LeafNamespace.Namespace}
    {records : SmzaRp05FilteredDecoderInstability.RawRecords}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (positions : Fin 38 → Position)
    (heads tails : List (List Goldilocks)) (points : Fin 6 → Goldilocks)
    (checks : CurrentTwelveAuthenticatedChecks claims positions heads tails points)
    (queryShape : query.val = Finset.univ.image positions)
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients)
    (candidate : DecodedSource Goldilocks (Fin 5) 140)
    (decoded : responseDecoder SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint
      405 data masks response coefficients = some candidate)
    (accepted : query.val ⊆ responseSupport
      SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405 data masks response coefficients)
    (dataBinding : ∀ column : Fin 140, ∀ index, index ∈ query.val →
      data column.val index = SmzaQ38OracleExtraction.committedColumnValue
        (authenticatedReadbackOracle claims) column index) :
    query ∈ currentLvcsBadQueryEvent candidate.data points (currentStageClaims heads tails) ∨
      ∀ combination, currentStageClaims heads tails combination =
        SmzaQ38LvcsOpening.rowCombination candidate.data points combination := by
  classical
  by_cases discrepancy : ∃ combination,
      SmzaQ38LvcsOpening.discrepancy candidate.data points
        (currentStageClaims heads tails) combination ≠ 0
  · exact Or.inl (authenticated_same_run_query_mem_current_bad_event claims positions
      heads tails points checks queryShape candidate.data
      (recovered_rows_match_authenticated_query claims data masks response coefficients
        candidate decoded accepted dataBinding) discrepancy)
  · exact Or.inr (exact_combinations_of_no_discrepancy candidate.data points
      (currentStageClaims heads tails) discrepancy)

/-- Exhaust the actual current decoder, rather than assuming its success.
On an accepted query its failure is the current MCA event; on success the
same reconstructed rows either give the current LVCS event or all twelve
exact polynomial identities. This is deterministic and preserves the same
query, response, table, and authenticated readback throughout. -/
theorem accepted_current_checks_bad_or_recovered
    {ns : SmzaRp05LeafNamespace.Namespace}
    {records : SmzaRp05FilteredDecoderInstability.RawRecords}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (positions : Fin 38 → Position)
    (heads tails : List (List Goldilocks)) (points : Fin 6 → Goldilocks)
    (checks : CurrentTwelveAuthenticatedChecks claims positions heads tails points)
    (queryShape : query.val = Finset.univ.image positions)
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients)
    (accepted : query.val ⊆ responseSupport
      SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405 data masks response coefficients)
    (dataBinding : ∀ column : Fin 140, ∀ index, index ∈ query.val →
      data column.val index = SmzaQ38OracleExtraction.committedColumnValue
        (authenticatedReadbackOracle claims) column index) :
    query ∈ currentAcceptedExtractionFailureEvent data masks response coefficients ∨
      ∃ candidate : DecodedSource Goldilocks (Fin 5) 140,
        responseDecoder SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint
          405 data masks response coefficients = some candidate ∧
        (query ∈ currentLvcsBadQueryEvent candidate.data points
          (currentStageClaims heads tails) ∨
          ∀ combination, currentStageClaims heads tails combination =
            SmzaQ38LvcsOpening.rowCombination candidate.data points combination) := by
  classical
  by_cases failed : responseDecoder SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint
      405 data masks response coefficients = none
  · exact Or.inl (accepted_query_and_failed_extraction_mem_event
      data masks response coefficients query accepted failed)
  · obtain ⟨candidate, decoded⟩ := Option.ne_none_iff_exists'.mp failed
    exact Or.inr ⟨candidate, decoded,
      recovered_current_checks_bad_or_exact claims positions heads tails points
        checks queryShape data masks response coefficients candidate decoded
        accepted dataBinding⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentRecoveredQueryBridge
