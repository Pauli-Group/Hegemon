import Mca38UniversalMatrixEvent
import SmzaRp05CurrentUniversalMatrixTransport
import HegemonCrypto.CmsClassicalDatabase
import HegemonCrypto.FiniteFieldSampling

/-!
# Current-map response-universal DECS matrix loss

The current evaluation map uses the transported universal 405-degree line
count.  The resulting matrix event still quantifies over every later bounded
response; this file makes no fixed-response or independence assumption.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixLoss

open HegemonCrypto.SmallWood.V8Smz9McaRecovery
open HegemonCrypto.SmallWood.Mca38UniversalMatrixEvent
open HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406
open HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixTransport
open HegemonCrypto.FiniteFieldSampling
open HegemonCrypto.CmsClassicalDatabase
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 20000

abbrev Position := Fin domainSize
abbrev Coefficients := Fin 140 → Fin 5 → Goldilocks

def currentMatrixBad (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks) (coefficients : Coefficients) : Prop :=
  BadMatrix evaluationPoint 405 65536 data masks coefficients

def currentBadMatrices (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks) : Finset Coefficients :=
  badMatrices evaluationPoint 405 65536 data masks 140

def currentMatrixLoss : Rat :=
  ((140 * 12310499043179 : Nat) : Rat) /
    Fintype.card (Fin 5 → Goldilocks)

theorem output_density_of_card_bound {A B : Type*} [Fintype A] [Fintype B]
    [Nonempty A] [Nonempty B] (event : A → Prop) (budget : Nat)
    (bound : (Finset.univ.filter event).card * Fintype.card B ≤
      Fintype.card A * budget) :
    outputEventProbability event ≤ (budget : Rat) / Fintype.card B := by
  classical
  have aPositive : (0 : Rat) < Fintype.card A := by exact_mod_cast Fintype.card_pos
  have bPositive : (0 : Rat) < Fintype.card B := by exact_mod_cast Fintype.card_pos
  unfold outputEventProbability
  apply (div_le_div_iff₀ aPositive bPositive).2
  exact_mod_cast (by simpa only [Nat.mul_comm] using bound :
    (Finset.univ.filter event).card * Fintype.card B ≤ budget * Fintype.card A)

theorem current_matrix_bad_card_bound
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks) :
    (badMatrices evaluationPoint 405 65536 data masks 140).card *
        Fintype.card (Fin 5 → Goldilocks) ≤
      Fintype.card Coefficients * (140 * 12310499043179) := by
  have lineBound : ∀ (column : Fin 140) (prior : Fin 5 → Position → Goldilocks),
      (badLineLabels evaluationPoint 405 65536 prior (data column.val)).card ≤
        12310499043179 := by
    intro column prior
    exact current_universal_badLineLabels_65536 prior (data column.val)
  have bound := universal_bad_matrix_card_bound
    (F := Goldilocks) (Row := Fin 5) evaluationPoint 405 65536
    data masks 140 12310499043179 lineBound
  simpa only [Coefficients, Fintype.card_fun, Fintype.card_fin] using bound

theorem current_gamma_card :
    Fintype.card (Fin 5 → Goldilocks) = goldilocksModulus ^ 5 := by
  rw [Fintype.card_fun, Fintype.card_fin, goldilocks_card]

theorem current_matrix_bad_output_density
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks) :
    outputEventProbability (currentMatrixBad data masks) ≤ currentMatrixLoss := by
  classical
  have sameSet : (Finset.univ.filter (currentMatrixBad data masks)) =
      currentBadMatrices data masks := by
    ext coefficients
    simp only [currentMatrixBad, currentBadMatrices, badMatrices,
      Finset.mem_filter, Finset.mem_univ, true_and]
  have bound : (Finset.univ.filter (currentMatrixBad data masks)).card *
      Fintype.card (Fin 5 → Goldilocks) ≤
        Fintype.card Coefficients * (140 * 12310499043179) := by
    rw [sameSet]
    exact current_matrix_bad_card_bound data masks
  have density := output_density_of_card_bound (A := Coefficients)
    (B := Fin 5 → Goldilocks) (currentMatrixBad data masks)
    (140 * 12310499043179) bound
  simpa only [currentMatrixLoss] using density

theorem current_matrix_loss_eq_p5 :
    currentMatrixLoss =
      ((140 * 12310499043179 : Nat) : Rat) /
        (goldilocksModulus : Rat) ^ 5 := by
  unfold currentMatrixLoss
  rw [current_gamma_card]
  norm_num [Nat.cast_pow]

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentUniversalMatrixLoss
