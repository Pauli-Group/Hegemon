import SmzaRp05CurrentTwelveCalculated
import SmzaRp05CurrentQ38DetectionProbability

/-! Current same-record query event: calculated verifier checks and decoded
rows imply either exact polynomial equality or the current LVCS miss event.
This core deliberately does not construct an independently chosen interpolation
support or assert a probability law for post-query data. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentQueryEventCore

open Polynomial
open SmzaRp05CurrentTwelveCalculated
open SmzaRp05CurrentQ38DetectionProbability
open SmzaQ38McaSourceBinding
open SmzaQ38Recovery
open SmzaQ38OracleExtraction
open SmzaRp04ChronologicalAlgebra
open SmzaRp05TracePrefixes
open SmzaRp05Q38CurrentRebinding
open SmzaRp05AcceptedQ38AgreementBridge
open SmzaRp05GlobalOpeningReadback
open SmzaRp05FilteredDecoderInstability
open SmzaRecordedTracePath
open V8Smz9CoherentMerkleGeometry
open HegemonCrypto.SmallWood.SmzaRp04RawRoleSampling
open V8Smz9CappedRawSampler V8Smz9RawCounterCompiler
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

-- Keep the 38-subset instance opaque while elaborating event membership;
-- unfolding its enumeration expands the 2^23-position domain.
attribute [local irreducible] HegemonCrypto.SmallWood.V8Smz9McaRecovery.querySampleFintype

/-- The exact oracle view represented by the bytes in one accepted global
readback.  This is a pointwise decoded oracle, not a replacement for the
execution's Born law. -/
def authenticatedReadbackOracle {ns : SmzaRp05LeafNamespace.Namespace}
    {records : RawRecords} {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query) :
    SmzaQ38OracleExtraction.CommittedOracle :=
  fun index row => decodedOracle claims index row


/-- Stage polynomials are the claimed family for the current-map finite
event. -/
def currentStageClaims (heads tails : List (List Goldilocks)) :
    SmzaQ38LvcsOpening.ClaimedPolynomials :=
  fun combination => currentQueryPolynomial heads tails combination.1 combination.2

/-- The calculated 406-node polynomial checks are literally verifier opening
checks against the sampled leaves of that same global readback, for the
canonical choice `claimed (opening, block) = currentQueryPolynomial ...`.
The proof uses `queryShape` to identify the exact 38 checked positions. -/
theorem authenticated_current_checks_are_oracle_opening_checks
    {ns : SmzaRp05LeafNamespace.Namespace} {records : RawRecords}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (positions : Fin 38 → Position)
    (heads tails : List (List Goldilocks))
    (points : Fin 6 → Goldilocks)
    (checks : CurrentTwelveAuthenticatedChecks claims positions heads tails points)
    (queryShape : query.val = Finset.univ.image positions) :
    CurrentOracleOpeningChecks (authenticatedReadbackOracle claims) points
      (currentStageClaims heads tails) query := by
  intro combination index member
  rw [queryShape, Finset.mem_image] at member
  obtain ⟨j, _jmem, indexEq⟩ := member
  subst index
  have authenticated := checks.2 combination.1 combination.2 j (by
    rw [queryShape]
    exact Finset.mem_image.mpr ⟨j, Finset.mem_univ _, rfl⟩)
  have cellEq (coefficient : Fin 70) :
      decodedOracle claims (positions j)
          ⟨(SmzaQ38LvcsOpening.blockRow combination.2 coefficient).val, by
            have hb := combination.2.isLt
            have hc := coefficient.isLt
            unfold HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount
              HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta
              SmzaQ38LvcsOpening.blockRow
            omega⟩ =
        decodedOracle claims (positions j)
          ⟨70 * combination.2.val + coefficient.val, by
            have hb := combination.2.isLt
            have hc := coefficient.isLt
            unfold HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount
              HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta
            omega⟩ := by
    congr 1
    apply Fin.ext
    simp [SmzaQ38LvcsOpening.blockRow, Nat.mul_comm]
  have sumEq :
      (∑ coefficient : Fin 70,
        points combination.1 ^ coefficient.val *
          wordToGoldilocks (decodedOracle claims (positions j)
            ⟨(SmzaQ38LvcsOpening.blockRow combination.2 coefficient).val, by
              have hb := combination.2.isLt
              have hc := coefficient.isLt
              unfold HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount
                HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta
                SmzaQ38LvcsOpening.blockRow
              omega⟩)) =
      (∑ coefficient : Fin 70,
        points combination.1 ^ coefficient.val *
          wordToGoldilocks (decodedOracle claims (positions j)
            ⟨70 * combination.2.val + coefficient.val, by
              have hb := combination.2.isLt
              have hc := coefficient.isLt
              unfold HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount
                HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta
              omega⟩)) := by
    apply Finset.sum_congr rfl
    intro coefficient _
    rw [cellEq coefficient]
  change (currentQueryPolynomial heads tails combination.1 combination.2).eval
      (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint (positions j)) =
    ∑ coefficient : Fin 70,
      points combination.1 ^ coefficient.val *
        wordToGoldilocks (decodedOracle claims (positions j)
          ⟨(SmzaQ38LvcsOpening.blockRow combination.2 coefficient).val, by
            have hb := combination.2.isLt
            have hc := coefficient.isLt
            unfold HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsRowCount
              HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsEta
              SmzaQ38LvcsOpening.blockRow
            omega⟩)
  exact authenticated.trans sumEq.symm

/-- Generic algebraic implication, kept separate from the concrete Lagrange
claim so kernel checking never needs to expand a 406-point interpolant. -/
theorem oracle_checks_nonzero_mem_current_bad_event
    (oracle : SmzaQ38OracleExtraction.CommittedOracle)
    (rows : RecoveredRows) (points : Fin 6 → Goldilocks)
    (claimed : SmzaQ38LvcsOpening.ClaimedPolynomials) (query : Query)
    (rowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) =
        SmzaQ38OracleExtraction.committedColumnValue oracle row index)
    (checked : CurrentOracleOpeningChecks oracle points claimed query)
    (nonzero : ∃ combination,
      SmzaQ38LvcsOpening.discrepancy rows points claimed combination ≠ 0) :
    query ∈ currentLvcsBadQueryEvent rows points claimed := by
  apply current_not_detected_mem_lvcs_bad_event rows points claimed query
  intro detected
  have recovered := current_accepted_lvcs_combinations_are_recovered
    oracle rows points claimed query rowAgreement checked detected
  obtain ⟨combination, discrepancyNonzero⟩ := nonzero
  apply discrepancyNonzero
  exact sub_eq_zero.mpr (recovered combination)


set_option maxHeartbeats 1000000 in
set_option diagnostics true in
/-- Same-run calculated and authenticated current checks put any nonzero
discrepancy against the supplied fixed current-map `rows` into the current
finite miss event, provided those rows agree with the same readback at the
current evaluation points.  Crucially this does not claim that historical
`TwelveLvcsChecks` establishes `currentRowAgreement`: its source point map is
the old `SmzaQ38OracleExtraction.smz9EvaluationPoint`. -/
theorem authenticated_same_run_query_mem_current_bad_event
    {ns : SmzaRp05LeafNamespace.Namespace} {records : RawRecords}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (positions : Fin 38 → Position)
    (heads tails : List (List Goldilocks))
    (points : Fin 6 → Goldilocks)
    (checks : CurrentTwelveAuthenticatedChecks claims positions heads tails points)
    (queryShape : query.val = Finset.univ.image positions)
    (rows : RecoveredRows)
    (currentRowAgreement : ∀ row index, index ∈ query.val →
      (rows row).eval (SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint index) =
        SmzaQ38OracleExtraction.committedColumnValue
          (authenticatedReadbackOracle claims) row index)
    (nonzero : ∃ combination,
      SmzaQ38LvcsOpening.discrepancy rows points
        (currentStageClaims heads tails) combination ≠ 0) :
    query ∈ currentLvcsBadQueryEvent rows points (currentStageClaims heads tails) := by
  exact oracle_checks_nonzero_mem_current_bad_event
    (authenticatedReadbackOracle claims) rows points (currentStageClaims heads tails)
    query currentRowAgreement
    (authenticated_current_checks_are_oracle_opening_checks
      claims positions heads tails points checks queryShape) nonzero



end
end HegemonCrypto.SmallWood.SmzaRp05CurrentQueryEventCore
