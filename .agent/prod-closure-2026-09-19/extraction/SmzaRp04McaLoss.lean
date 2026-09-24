import SmzaRp04McaRoleCells
import Mca38SeparateStageLedger

/-! The proved MCA role densities meet the unchanged numerical ledger.
This is the classical local loss, not a stand-alone quantum security claim. -/
namespace HegemonCrypto.SmallWood.SmzaRp04McaLoss

open SmzaRp04McaRoleCells SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open Mca38SeparateStageLedger
set_option exponentiation.threshold 1024
set_option maxRecDepth 10000

theorem matrix_loss_eq_ledger : matrixLoss = matrixError := by
  simp only [matrixLoss, matrixError, Fintype.card_fun, Fintype.card_fin,
    goldilocks_card, Nat.cast_pow]
  norm_num [Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]

theorem small_support_loss_le : smallSupportLoss ≤ (1 / 128 : Rat)^38 := by
  have domain : Fintype.card Position = 8388608 := by
    simp only [Position, Fintype.card_fin]
    rfl
  rw [smallSupportLoss, domain]
  exact q38_small_support_probability_le

theorem combined_mca_local_loss_below_265_bits :
    matrixLoss + smallSupportLoss < (1 / 2 : Rat)^265 := by
  rw [matrix_loss_eq_ledger]
  exact (add_le_add (le_refl matrixError) small_support_loss_le).trans_lt
    separate_decs_errors_below_265_bits

end HegemonCrypto.SmallWood.SmzaRp04McaLoss
