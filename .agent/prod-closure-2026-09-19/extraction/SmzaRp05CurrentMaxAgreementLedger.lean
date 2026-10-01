import SmzaRp05CurrentMaxAgreementRecovery
import Mca38SeparateStageLedger

/-! Numeric close for the current-map finite matrix-by-q38 maximum-agreement
event.  This only closes the classical finite-experiment loss; it does not
transport that law to a physical Born distribution. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementLedger

open HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery
open HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixLoss
open HegemonCrypto.SmallWood.Mca38SeparateStageLedger
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

abbrev CurrentPosition :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementRecovery.Position

theorem current_small_support_loss_le_128 :
    (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
        Nat.choose (Fintype.card CurrentPosition) 38 ≤ (1 / 128 : Rat)^38 := by
  have domain : Fintype.card CurrentPosition = 8388608 := by
    simp only [CurrentPosition, Fintype.card_fin,
      HegemonCrypto.SmallWood.SmzaQ38OracleExtraction.decsDomainSize,
      HegemonCrypto.SmallWood.V8Smz9LogicalOracle.decsDomainSize]
    norm_num
  simpa only [currentAgreementThreshold, domain] using q38_small_support_probability_le

theorem current_matrix_loss_eq_matrix_error : currentMatrixLoss = matrixError := by
  rw [current_matrix_loss_eq_p5]
  unfold matrixError
  norm_num [goldilocksModulus]

theorem current_max_agreement_loss_le_ledger_terms
    (data : Nat → CurrentPosition → Goldilocks)
    (masks : Fin 5 → CurrentPosition → Goldilocks)
    (response : ResponseRule) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (currentAcceptedExtractionFailureEvent data masks response) ≤
      matrixError + (1 / 128 : Rat)^38 := by
  calc
    _ ≤ currentMatrixLoss +
        (Nat.choose (currentAgreementThreshold - 1) 38 : Rat) /
          Nat.choose (Fintype.card CurrentPosition) 38 :=
      current_q38_max_agreement_failure_probability_le data masks response
    _ ≤ matrixError + (1 / 128 : Rat)^38 := by
      rw [current_matrix_loss_eq_matrix_error]
      exact add_le_add le_rfl current_small_support_loss_le_128

theorem current_max_agreement_loss_below_265_bits
    (data : Nat → CurrentPosition → Goldilocks)
    (masks : Fin 5 → CurrentPosition → Goldilocks)
    (response : ResponseRule) :
    V8Smz9RobustQueryMismatch.FiniteEvents.jointProbability
        (currentAcceptedExtractionFailureEvent data masks response) <
      (1 / 2 : Rat)^265 := by
  exact (current_max_agreement_loss_le_ledger_terms data masks response).trans_lt
    separate_decs_errors_below_265_bits

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentMaxAgreementLedger
