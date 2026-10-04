import SmzaRp05Current406EventSpec
import SmzaRp05SecurityLedger
import SmzaRp05CurrentMaxAgreementLedger

/-! Numeric closure for the ordinary current-406 scalar budget.  This is an
arithmetic endpoint only: it does not establish inclusion of an accepted
execution in the current-406 events. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinarySecurityLedger

open SmzaChallengeStageTargets
open SmzaRp05Current406EventSpec
open SmzaRp05CurrentUniversalMatrixLoss
open SmzaRp04FourRoleLedger
open SmzaRp04McaLoss
open SmzaRp05SecurityLedger
open SmzaRp05CurrentMaxAgreementLedger

noncomputable section
set_option autoImplicit false
set_option exponentiation.threshold 1024

/-- Sum of the exact current-406 role densities. -/
def current406LocalLoss : Rat :=
  current406RoleLoss .decsMatrix + current406RoleLoss .piopMatrix +
    current406RoleLoss .piopOpening + current406RoleLoss .decsSample

/-- The scalar loss when the incoming state has unit norm, the output alphabet
has cardinality `2^512`, and the charged prefix has squared norm at most one.
The second sum is the separate collision term already present in the ordinary
scalar endpoint. -/
def currentOrdinaryScalarLoss (queries depth : Nat) : Rat :=
  6 * (queries : Rat)^2 * current406LocalLoss +
    (168 * (queries : Rat)^3 + 16 * (depth : Rat)) / (2 : Rat)^512

theorem current406_local_loss_eq_historical :
    current406LocalLoss = fourRoleLocalLoss := by
  unfold current406LocalLoss fourRoleLocalLoss current406RoleLoss sourceOnlyRoleLoss
  rw [current_matrix_loss_eq_matrix_error, matrix_loss_eq_ledger]
  rfl

/-- Exact coefficient identity for the role budgets, readout, and collision
budgets in the current ordinary scalar theorem. -/
theorem current_ordinary_scalar_identity (queries depth : Nat) :
    (∑ role : Role,
        (6 * (queries : ℝ)^2 * current406Bound role queries)) +
      16 * (depth : ℝ) / (2 : ℝ)^512 +
      (∑ _role : Role,
        (6 * (queries : ℝ)^2 *
          (((queries : Rat) / (2 : Rat)^512 : Rat) : ℝ))) =
      ((currentOrdinaryScalarLoss queries depth : Rat) : ℝ) := by
  have roles : (Finset.univ : Finset Role) =
      {.decsMatrix, .piopMatrix, .piopOpening, .decsSample} := by
    ext role
    cases role <;> simp
  rw [roles]
  simp [current406Bound, current406LocalLoss, currentOrdinaryScalarLoss]
  ring

/-- The identity stays valid after multiplying role losses by a common
incoming squared norm.  With unit incoming norm and prefix squared norm at
most one, the concrete budgets are bounded by this expression. -/
theorem weighted_current_ordinary_scalar_le
    (queries depth : Nat) (incomingNorm prefixNorm : ℝ)
    (incomingUnit : incomingNorm = 1)
    (_prefixNonnegative : 0 ≤ prefixNorm) (prefixLeOne : prefixNorm ≤ 1) :
    (∑ role : Role,
        (6 * (queries : ℝ)^2 * current406Bound role queries) * incomingNorm) +
      (16 * (depth : ℝ) / (2 : ℝ)^512) * prefixNorm +
      (∑ _role : Role,
        (6 * (queries : ℝ)^2 *
          (((queries : Rat) / (2 : Rat)^512 : Rat) : ℝ)) * incomingNorm) ≤
      ((currentOrdinaryScalarLoss queries depth : Rat) : ℝ) := by
  rw [incomingUnit]
  have readoutNonnegative : 0 ≤ 16 * (depth : ℝ) / (2 : ℝ)^512 := by positivity
  have readoutBound :
      (16 * (depth : ℝ) / (2 : ℝ)^512) * prefixNorm ≤
        16 * (depth : ℝ) / (2 : ℝ)^512 :=
    by simpa only [mul_one] using
      (mul_le_mul_of_nonneg_left prefixLeOne readoutNonnegative)
  calc
    _ = ((∑ role : Role,
          (6 * (queries : ℝ)^2 * current406Bound role queries)) +
        (16 * (depth : ℝ) / (2 : ℝ)^512) * prefixNorm) +
          (∑ role : Role,
            (6 * (queries : ℝ)^2 *
              (((queries : Rat) / (2 : Rat)^512 : Rat) : ℝ))) := by ring
    _ ≤ ((∑ role : Role,
          (6 * (queries : ℝ)^2 * current406Bound role queries)) +
        (16 * (depth : ℝ) / (2 : ℝ)^512)) +
          (∑ role : Role,
            (6 * (queries : ℝ)^2 *
              (((queries : Rat) / (2 : Rat)^512 : Rat) : ℝ))) := by
      apply add_le_add
      · simpa only [add_comm] using
          (add_le_add_right readoutBound
            (∑ role : Role,
              (6 * (queries : ℝ)^2 * current406Bound role queries)))
      · exact le_of_eq rfl
    _ = ((currentOrdinaryScalarLoss queries depth : Rat) : ℝ) := by
      exact current_ordinary_scalar_identity queries depth

/-- The closed current ordinary scalar budget is covered by the existing
fresh-extraction numerical ledger whenever the ordinary query cap holds and
the prefix depth does not exceed the query count. -/
theorem current_ordinary_scalar_le_fresh
    (queries depth : Nat) (depthWithin : depth ≤ queries) :
    currentOrdinaryScalarLoss queries depth ≤ freshExtractionLoss queries := by
  have roleLossEq := current406_local_loss_eq_historical
  have depthCast : (depth : Rat) ≤ (queries : Rat) := by exact_mod_cast depthWithin
  by_cases zero : queries = 0
  · have depthZero : depth = 0 := Nat.eq_zero_of_le_zero (by simpa [zero] using depthWithin)
    simp [currentOrdinaryScalarLoss, freshExtractionLoss, zero, depthZero]
  · have oneLe : (1 : Rat) ≤ (queries : Rat) := by
      exact_mod_cast Nat.one_le_iff_ne_zero.mpr zero
    have sqOne : (1 : Rat) ≤ (queries : Rat)^2 := by
      nlinarith [sq_nonneg ((queries : Rat) - 1)]
    have queryLeCube : (queries : Rat) ≤ (queries : Rat)^3 := by
      calc
        (queries : Rat) = (queries : Rat) * 1 := by ring
        _ ≤ (queries : Rat) * (queries : Rat)^2 :=
          mul_le_mul_of_nonneg_left sqOne (by positivity)
        _ = (queries : Rat)^3 := by ring
    unfold currentOrdinaryScalarLoss freshExtractionLoss
    rw [roleLossEq]
    have localNonnegative : (0 : Rat) ≤ fourRoleLocalLoss := by
      unfold fourRoleLocalLoss
      exact add_nonneg
        (add_nonneg
          (add_nonneg (source_only_role_loss_nonnegative .decsMatrix)
            (source_only_role_loss_nonnegative .piopMatrix))
          (source_only_role_loss_nonnegative .piopOpening))
        (source_only_role_loss_nonnegative .decsSample)
    have localPart :
        6 * (queries : Rat)^2 * fourRoleLocalLoss ≤
          12 * (queries : Rat)^2 * fourRoleLocalLoss := by nlinarith
    have residual :
        168 * (queries : Rat)^3 + 16 * (depth : Rat) ≤
          9806 * (queries : Rat)^3 + 2 * (queries : Rat) := by
      have depthTerm :
          16 * (depth : Rat) ≤ 16 * (queries : Rat) :=
        mul_le_mul_of_nonneg_left depthCast (by norm_num)
      calc
        _ ≤ 168 * (queries : Rat)^3 + 16 * (queries : Rat) := by linarith
        _ ≤ _ := by nlinarith [queryLeCube]
    have divisorPositive : (0 : Rat) < (2 : Rat)^512 := by positivity
    have residualDiv := div_le_div_of_nonneg_right residual divisorPositive.le
    exact add_le_add localPart residualDiv

theorem current_ordinary_scalar_below_130_bits
    (queries depth : Nat) (bounded : queries ≤ 3 * 2^64)
    (depthWithin : depth ≤ queries) :
    currentOrdinaryScalarLoss queries depth < 1 / (2 : Rat)^130 :=
  lt_of_le_of_lt (current_ordinary_scalar_le_fresh queries depth depthWithin)
    (fresh_extraction_loss_below_130_bits queries bounded)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinarySecurityLedger
