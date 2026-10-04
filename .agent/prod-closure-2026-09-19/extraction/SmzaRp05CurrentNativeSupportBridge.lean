import SmzaRp05CurrentAcceptedQuerySupport

/-! A representation-normalized interface to the native five-check support
lemma. Keeping the public decoder names in this signature avoids reducing
concrete executable row calculations merely to unfold a private abbreviation.
The mathematical premises and support conclusion are unchanged. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentNativeSupportBridge

open SmzaRp05CurrentAcceptedQuerySupport
open V8SmzaOracleParser (RawDigest)
open HegemonCrypto.CanonicalBytes (Byte)

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

theorem support_of_native_checks
    {ns : SmzaRp05LeafNamespace.Namespace}
    {records : SmzaRp05FilteredDecoderInstability.RawRecords}
    {root : RawDigest} {query : Query}
    (claims : SmzaRp05GlobalOpeningReadback.GlobalQueryReadback ns records root query)
    (positions : Fin 38 → Position)
    (queryImage : query.val = Finset.univ.image positions)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (rows : List (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (salt : List Byte) (tapes : List (List Byte)) (indexes : List Nat)
    (indexBinding : ∀ j : Fin 38, (positions j).val = indexes.getD j.val 0)
    (leafBytes : ∀ j : Fin 38,
      (claims.leaf (positions j)).bytes =
        SmzaRp05PcsMerklePayload.normalizedLeafPayload salt (tapes.getD j.val [])
          (indexes.getD j.val 0)
          (SmzaRp05DecsResponseProjection.decodeFieldRow (rows.getD j.val []))
          (decs.maskingEvals.getD j.val []))
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks) (response : ResponseRule)
    (gamma : List (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (evalPoints : List SmzaRp05ExecutableChallengeStage.FieldWord)
    (polynomials : List SmzaRp05DecsResponseProjection.FieldRow)
    (restore : SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
      rows gamma evalPoints 140 368 = some polynomials)
    (native : SmzaRp05ExecutablePcsClosureMca406.NativeFiveMcaChecks406
      salt tapes indexes rows gamma decs.maskingEvals evalPoints polynomials)
    (pointBinding : ∀ j : Fin 38,
      (SmzaRp05DecsResponseProjection.decodeFieldRow evalPoints).getD j.val 0 =
        SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint (positions j))
    (dataBinding : ∀ j : Fin 38, ∀ column : Fin 140,
      data column.val (positions j) = V8Smz9OracleExtraction.wordToGoldilocks
        (SmzaRp05TracePrefixes.fieldWordAt
          (claims.leaf (positions j)).bytes (14 + column.val)))
    (maskBinding : ∀ j : Fin 38, ∀ row : Fin 5,
      masks row (positions j) = V8Smz9OracleExtraction.wordToGoldilocks
        (SmzaRp05TracePrefixes.fieldWordAt
          (claims.leaf (positions j)).bytes (155 + row.val)))
    (responseAtSample : ∀ row : Fin 5,
      V8Smz9McaRecovery.responsePolynomials (response (sampledCoefficients gamma)) row =
        SmzaRp05ExecutablePcsClosureAlgebra.coefficientPolynomial
          (polynomials.getD row.val [])) :
    query.val ⊆ V8Smz9McaDecoder.responseSupport
      SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405
      data masks response (sampledCoefficients gamma) := by
  exact (accepted_query_subset_fixed_response_support claims positions queryImage
    decs rows salt tapes indexes indexBinding leafBytes data masks response
    gamma evalPoints polynomials restore native pointBinding dataBinding maskBinding
    responseAtSample).2.2

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentNativeSupportBridge
