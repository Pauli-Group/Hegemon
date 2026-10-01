import SmzaRp05CurrentDecoderLabelInclusion

/-! Identifies the accepted current-map decoder alternatives with the current
source label. The serialized claim equality is kept explicit here and must be
provided by the source opening readback, not presumed by a final endpoint. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOutcomeLabelBridge

open SmzaRp05CurrentTracePrefixes406
open SmzaRp05CurrentDecoderLabelInclusion
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentQueryEventCore (currentStageClaims)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
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
attribute [local irreducible]
  SmzaRp05CurrentQ38DetectionProbability.currentLvcsBadQueryEvent

/-- This is a deterministic transport of the already derived alternatives,
not an assumption that accepted executions satisfy the bounded role event. -/
theorem decoder_outcome_is_current_label_bad_or_exact
    (oracle : CurrentCommittedOracle) (fpp : Payload)
    (coefficients : CurrentCoefficients) (points : Fin 6 → Goldilocks)
    (heads tails : List (List Goldilocks)) (claimed : Fixed406Coefficients)
    (matrixGood : ¬ currentMatrixBad (oracleData oracle) (oracleMasks oracle) coefficients)
    (query : CurrentQuery)
    (claimsRead : claimedPolynomials claimed = currentStageClaims heads tails)
    (outcome : CurrentDecoderOutcome (oracleData oracle) (oracleMasks oracle)
      (currentResponseRule406 fpp) coefficients heads tails points query) :
    currentSourceBad406 (currentSourcePrefix406 oracle fpp coefficients points claimed
      matrixGood) query ∨
      ∃ source : DecodedSource Goldilocks (Fin 5) 140,
        currentSourceDecoder406 oracle fpp coefficients = some source ∧
        ∀ combination, currentStageClaims heads tails combination =
          SmzaQ38LvcsOpening.rowCombination source.data points combination := by
  rcases outcome with failed | ⟨source, recovered, missed | exactClaims⟩
  · exact Or.inl (decoder_failure_is_current_prefix_bad oracle fpp coefficients
      points claimed matrixGood query failed)
  · apply Or.inl
    apply decoded_lvcs_miss_is_current_prefix_bad oracle fpp coefficients
      points claimed matrixGood query source recovered
    rw [claimsRead]
    exact missed
  · exact Or.inr ⟨source, recovered, exactClaims⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOutcomeLabelBridge
