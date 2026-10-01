import SmzaRp05CurrentLabelReadback

/-! The current decoder alternatives are the bad predicates carried by the
current source prefix, not the historical 388-map predicates. These lemmas
only identify that deterministic event; probability is charged separately by
CurrentSourceRoleEvent and CurrentPhysicalEventBound. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentDecoderLabelInclusion

open scoped Classical
open SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentMaxAgreementRecovery
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentQ38DetectionProbability
open SmzaRp04ChronologicalAlgebra (Fixed406Coefficients claimedPolynomials)
open SmzaQ38McaSourceBinding (oracleData oracleMasks)
open SmzaRp05TracePrefixes (Payload)
open V8Smz9McaDecoder (DecodedSource)

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
noncomputable section

attribute [local irreducible] V8Smz9McaRecovery.querySampleFintype
attribute [local irreducible] V8Smz9McaDecoder.decodeSource
  V8Smz9McaDecoder.responseSupport

theorem decoder_failure_is_current_prefix_bad
    (oracle : CurrentCommittedOracle) (fpp : Payload)
    (coefficients : CurrentCoefficients) (points : Fin 6 → Goldilocks)
    (claimed : Fixed406Coefficients)
    (matrixGood : ¬ currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients)
    (query : CurrentQuery)
    (failed : query ∈ currentAcceptedExtractionFailureEvent
      (oracleData oracle) (oracleMasks oracle) (currentResponseRule406 fpp) coefficients) :
    currentSourceBad406 (currentSourcePrefix406 oracle fpp coefficients points claimed
      matrixGood) query := by
  exact Or.inl failed

theorem decoded_lvcs_miss_is_current_prefix_bad
    (oracle : CurrentCommittedOracle) (fpp : Payload)
    (coefficients : CurrentCoefficients) (points : Fin 6 → Goldilocks)
    (claimed : Fixed406Coefficients)
    (matrixGood : ¬ currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients)
    (query : CurrentQuery) (source : DecodedSource Goldilocks (Fin 5) 140)
    (recovered : currentSourceDecoder406 oracle fpp coefficients = some source)
    (missed : query ∈ currentLvcsBadQueryEvent source.data points
      (claimedPolynomials claimed)) :
    currentSourceBad406 (currentSourcePrefix406 oracle fpp coefficients points claimed
      matrixGood) query := by
  obtain ⟨decoded, labelRead, rowsRead, pointsRead, claimsRead⟩ :=
    current_source_prefix_decoded_of_success
    oracle fpp coefficients points claimed matrixGood source recovered
  refine Or.inr ⟨decoded, labelRead, decoded.rowsDegree, ?_⟩
  simpa only [rowsRead, pointsRead, claimsRead] using missed

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentDecoderLabelInclusion
