import SmzaRp05AcceptedMca406
import SmzaRp05CurrentMaxAgreementRecovery
import SmzaRp05GlobalOpeningReadback

/-!
# Accepted RP05 q38 support conversion

This is the narrow converter from the source-shaped 406-term restoration
equations to the exact finite support predicate consumed by current maximum-
agreement recovery.  The row-data and mask functions, and the matrix-indexed
bounded response rule, are explicit inputs: their pre-query/fixed-family
provenance is deliberately not manufactured from the 38 post-query leaves.
The theorem below only proves that this same-run query is contained in the
support when those upstream families agree with authenticated leaf cells and
the response rule agrees with the actual restored polynomials at the sampled
matrix.

This is a finite event-interface theorem, not a construction of a pre-query
codeword family, a physical/QROM event transport, or a final soundness claim.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQuerySupport

open scoped BigOperators
open HegemonCrypto.SmallWood.V8Smz9McaRecovery
  (mixedWord extendCoefficients mixed_word_eq_sum responsePolynomials agreement mem_agreement)
open HegemonCrypto.SmallWood.V8Smz9McaDecoder (responseSupport)

set_option autoImplicit false
noncomputable section

abbrev Goldilocks := HegemonCrypto.SmallWood.Goldilocks
abbrev FieldWord := SmzaRp05ExecutableChallengeStage.FieldWord
abbrev FieldRow := SmzaRp05DecsResponseProjection.FieldRow
abbrev Position := SmzaRp05CurrentMaxAgreementRecovery.Position
abbrev Query := SmzaRp05CurrentMaxAgreementRecovery.Query
abbrev Coefficients := SmzaRp05CurrentMaxAgreementRecovery.Coefficients
abbrev ResponseRule := SmzaRp05CurrentMaxAgreementRecovery.ResponseRule
abbrev GlobalQueryReadback := SmzaRp05GlobalOpeningReadback.GlobalQueryReadback

private abbrev decodeFieldRow := SmzaRp05DecsResponseProjection.decodeFieldRow
private abbrev coefficientPolynomial :=
  SmzaRp05ExecutablePcsClosureAlgebra.coefficientPolynomial
private abbrev wordToGoldilocks := V8Smz9OracleExtraction.wordToGoldilocks
private abbrev fieldWordAt := SmzaRp05TracePrefixes.fieldWordAt
private abbrev smz9EvaluationPoint :=
  SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint

/-- The 5-by-140 matrix actually emitted by the post-Merkle DECS sampler,
transposed to the `Fin 140 → Fin 5` orientation used by the decoder. -/
def sampledCoefficients (gamma : List (List FieldWord)) : Coefficients :=
  fun column row =>
    (decodeFieldRow (gamma.getD row.val [])).getD column.val 0

/-- The finite-list `Fin 140` dot product is exactly the first 140 terms of
the recovery experiment's natural-number `mixedWord`. -/
theorem mixedWord_140_eq_fin_sum
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (coefficients : Coefficients) (row : Fin 5) (index : Position) :
    mixedWord data masks (extendCoefficients coefficients) 140 row index =
      masks row index +
        ∑ column : Fin 140, coefficients column row * data column.val index := by
  rw [mixed_word_eq_sum]
  have rangeEq :
      (∑ column ∈ Finset.range 140,
        extendCoefficients coefficients column row * data column index) =
      ∑ column : Fin 140, coefficients column row * data column.val index := by
    rw [← Fin.sum_univ_eq_sum_range]
    apply Finset.sum_congr rfl
    intro column _
    simp [extendCoefficients]
  rw [rangeEq]

/-- A successful current-profile response rule is represented by degree-405
polynomials for every matrix.  `responseAtSample` is the explicit bridge from
that pre-existing rule to the actual 406-coefficient restore output. -/
theorem accepted_query_subset_fixed_response_support
    {ns : SmzaRp05LeafNamespace.Namespace}
    {records : SmzaRp05FilteredDecoderInstability.RawRecords}
    {root : V8SmzaOracleParser.RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (positions : Fin 38 → Position)
    (queryImage : query.val = Finset.univ.image positions)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (rows : List (List FieldWord))
    (salt : List HegemonCrypto.CanonicalBytes.Byte)
    (tapes : List (List HegemonCrypto.CanonicalBytes.Byte))
    (indexes : List Nat)
    (indexBinding : ∀ j : Fin 38,
      (positions j).val = indexes.getD j.val 0)
    (leafBytes : ∀ j : Fin 38,
      (claims.leaf (positions j)).bytes =
        SmzaRp05PcsMerklePayload.normalizedLeafPayload
          salt (tapes.getD j.val []) (indexes.getD j.val 0)
          (decodeFieldRow (rows.getD j.val [])) (decs.maskingEvals.getD j.val []))
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule)
    (gamma : List (List FieldWord))
    (evalPoints : List FieldWord) (polynomials : List FieldRow)
    (restore : SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
      rows gamma evalPoints 140 368 = some polynomials)
    (native : SmzaRp05ExecutablePcsClosureMca406.NativeFiveMcaChecks406
      salt tapes indexes rows gamma decs.maskingEvals
      evalPoints polynomials)
    (pointBinding : ∀ j : Fin 38,
      (decodeFieldRow evalPoints).getD j.val 0 = smz9EvaluationPoint (positions j))
    (dataBinding : ∀ j : Fin 38, ∀ column : Fin 140,
      data column.val (positions j) = wordToGoldilocks
        (fieldWordAt (claims.leaf (positions j)).bytes (14 + column.val)))
    (maskBinding : ∀ j : Fin 38, ∀ row : Fin 5,
      masks row (positions j) = wordToGoldilocks
        (fieldWordAt (claims.leaf (positions j)).bytes (155 + row.val)))
    (responseAtSample : ∀ row : Fin 5,
      responsePolynomials (response (sampledCoefficients gamma)) row =
        coefficientPolynomial (polynomials.getD row.val [])) :
    (∀ j : Fin 38, (positions j).val = indexes.getD j.val 0) ∧
    SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
      rows gamma evalPoints 140 368 = some polynomials ∧
    query.val ⊆ responseSupport smz9EvaluationPoint 405 data masks response
      (sampledCoefficients gamma) := by
  refine ⟨indexBinding, restore, ?_⟩
  intro index member
  rw [queryImage] at member
  rcases Finset.mem_image.mp member with ⟨j, _jmem, indexEq⟩
  subst index
  change positions j ∈ agreement smz9EvaluationPoint
    (mixedWord data masks (extendCoefficients (sampledCoefficients gamma)) 140)
    (responsePolynomials (response (sampledCoefficients gamma)))
  rw [mem_agreement]
  intro row
  rw [responseAtSample row]
  have sampledData : ∀ column : Fin 140,
      data column.val (positions j) = wordToGoldilocks
        (fieldWordAt
          (SmzaRp05PcsMerklePayload.normalizedLeafPayload
            salt (tapes.getD j.val []) (indexes.getD j.val 0)
            (decodeFieldRow (rows.getD j.val [])) (decs.maskingEvals.getD j.val []))
          (14 + column.val)) := by
    intro column
    rw [← leafBytes j]
    exact dataBinding j column
  have sampledMask : masks row (positions j) = wordToGoldilocks
      (fieldWordAt
        (SmzaRp05PcsMerklePayload.normalizedLeafPayload
          salt (tapes.getD j.val []) (indexes.getD j.val 0)
          (decodeFieldRow (rows.getD j.val [])) (decs.maskingEvals.getD j.val []))
        (155 + row.val)) := by
    rw [← leafBytes j]
    exact maskBinding j row
  have mca := native row.val row.isLt j.val j.isLt
  rw [pointBinding j] at mca
  have sumEq :
      (∑ column : Fin 140,
        (decodeFieldRow (gamma.getD row.val [])).getD column.val 0 *
          wordToGoldilocks (fieldWordAt
            (SmzaRp05PcsMerklePayload.normalizedLeafPayload
              salt (tapes.getD j.val []) (indexes.getD j.val 0)
              (decodeFieldRow (rows.getD j.val [])) (decs.maskingEvals.getD j.val []))
            (14 + column.val))) =
      ∑ column : Fin 140,
        sampledCoefficients gamma column row * data column.val (positions j) := by
    apply Finset.sum_congr rfl
    intro column _
    rw [← sampledData column]
    rfl
  calc
    (coefficientPolynomial (polynomials.getD row.val [])).eval
        (smz9EvaluationPoint (positions j)) =
      wordToGoldilocks (fieldWordAt
        (SmzaRp05PcsMerklePayload.normalizedLeafPayload
          salt (tapes.getD j.val []) (indexes.getD j.val 0)
          (decodeFieldRow (rows.getD j.val [])) (decs.maskingEvals.getD j.val []))
        (155 + row.val)) +
        ∑ column : Fin 140,
          (decodeFieldRow (gamma.getD row.val [])).getD column.val 0 *
            wordToGoldilocks (fieldWordAt
              (SmzaRp05PcsMerklePayload.normalizedLeafPayload
                salt (tapes.getD j.val []) (indexes.getD j.val 0)
                (decodeFieldRow (rows.getD j.val [])) (decs.maskingEvals.getD j.val []))
              (14 + column.val)) := mca
    _ = mixedWord data masks (extendCoefficients (sampledCoefficients gamma))
        140 row (positions j) := by
      rw [← sampledMask, sumEq]
      exact (mixedWord_140_eq_fin_sum data masks
        (sampledCoefficients gamma) row (positions j)).symm

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQuerySupport
