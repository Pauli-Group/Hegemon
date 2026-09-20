import SmzaRp04McaLoss
import SmzaRp04RoleBadCells
import HegemonCrypto.CmsLifting

/-!
# Numerical RP04 four-role ledger

This file contains arithmetic only.  It instantiates the four checked RP04
role densities, including the response-universal MCA matrix event and the
later q38 small-support event, without importing the raw-sampler drafts.

The endpoint is deliberately not an accepted-execution theorem.  Identifying
the four role events with one accepted physical execution, and charging
transcript binding, commitment binding, semantic refinement, and lifetime
composition, remain separate obligations.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04FourRoleLedger

open SmzaChallengeStageTargets
open SmzaRp04ChronologicalAlgebra SmzaRp04RoleBadCells
open SmzaRp04McaRoleCells SmzaRp04McaLoss
open Mca38SeparateStageLedger
open V8Smz9PiopSoundness V8Smz9AdaptiveFiniteAccounting
open HegemonCrypto.CmsLifting

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024

/-- The four source-level densities.  This is the same arithmetic definition
as the raw MCA adapter's `completeRoleLoss`, restated here so this checked
numerical ledger does not depend on that still-integrating adapter. -/
def sourceOnlyRoleLoss : Role → Rat
  | .decsMatrix => matrixLoss
  | .piopMatrix => roleLoss .piopMatrix
  | .piopOpening => roleLoss .piopOpening
  | .decsSample => smallSupportLoss + roleLoss .decsSample

/-- Explicit four-role sum, with each density charged exactly once. -/
def fourRoleLocalLoss : Rat :=
  sourceOnlyRoleLoss .decsMatrix +
    sourceOnlyRoleLoss .piopMatrix +
    sourceOnlyRoleLoss .piopOpening +
    sourceOnlyRoleLoss .decsSample

/-- Bound the finite q38 root sample by factorial-cancelling power bounds.
In particular, the proof never unfolds the `choose 8388608 38` recurrence. -/
theorem q38_lvcs_loss_le_power_bound :
    q38LvcsLoss ≤
      12 * ((405 : Rat) / 8388571) ^ 38 := by
  have domain :
      Fintype.card SmzaQ38McaSourceBinding.Position = 8388608 := by
    simp only [SmzaQ38McaSourceBinding.Position, Fintype.card_fin]
    rfl
  rw [q38LvcsLoss, q38SingleRootLoss, domain]
  let a : Rat := Nat.choose 405 38
  let b : Rat := Nat.choose 8388608 38
  let f : Rat := Nat.factorial 38
  have aNonnegative : 0 ≤ a := Nat.cast_nonneg _
  have bPositive : 0 < b := by
    dsimp [b]
    exact_mod_cast (Nat.choose_pos (by norm_num : 38 ≤ 8388608))
  have fPositive : 0 < f := by
    dsimp [f]
    positivity
  have upper : a ≤ (405 : Rat) ^ 38 / f := Nat.choose_le_pow_div 38 405
  have lower : (8388571 : Rat) ^ 38 / f ≤ b := by
    simpa only [Nat.reduceAdd, Nat.reduceSub, Nat.cast_pow, Nat.cast_ofNat] using
      (Nat.pow_le_choose (α := Rat) 38 8388608)
  have upperMul : a * f ≤ (405 : Rat) ^ 38 :=
    (le_div_iff₀ fPositive).mp upper
  have lowerMul : (8388571 : Rat) ^ 38 ≤ b * f :=
    (div_le_iff₀ fPositive).mp lower
  have cross :
      a * (8388571 : Rat) ^ 38 ≤ (405 : Rat) ^ 38 * b := by
    calc
      _ ≤ a * (b * f) := mul_le_mul_of_nonneg_left lowerMul aNonnegative
      _ = (a * f) * b := by ring
      _ ≤ _ := mul_le_mul_of_nonneg_right upperMul bPositive.le
  have ratio :
      a / b ≤ (405 : Rat) ^ 38 / (8388571 : Rat) ^ 38 :=
    (div_le_div_iff₀ bPositive (by positivity)).mpr cross
  apply mul_le_mul_of_nonneg_left _ (by norm_num : (0 : Rat) ≤ 12)
  simpa only [a, b, div_pow] using ratio

/-- The PIOP-matrix, six-opening, and twelve-polynomial q38 densities together
are smaller than the already-counted response-universal matrix density. -/
theorem non_mca_role_losses_le_matrix_loss :
    roleLoss .piopMatrix + roleLoss .piopOpening + roleLoss .decsSample ≤
      matrixLoss := by
  have rootBound := q38_lvcs_loss_le_power_bound
  have arithmetic :
      ((1 : Rat) / 18446744069414584321) ^ 5 + epsilon3 +
          12 * ((405 : Rat) / 8388571) ^ 38 ≤ matrixError := by
    norm_num [epsilon3, correctedEpsilon3,
      correctionAwareOpeningTupleLowerBound, distinctOutsideOpeningTupleCount,
      admissibilityRejectedTupleUpperBound,
      openingAdmissibilityBadTupleCoefficient, correctionPolynomialDegree,
      pcsUnstackAdditionalForbiddenValues,
      V8QromAccounting.fallingProduct,
      V8Smz9QromAccounting.fallingProduct,
      V8Smz9QromAccounting.piopConsistencyDiscrepancyDegree,
      V8Smz9QromAccounting.batchedConstraintPolynomialDegree,
      V8Smz9QromAccounting.witnessPolynomialDegree,
      V8Smz9QromAccounting.relationDegree,
      V8Smz9QromAccounting.packingFactor,
      V8Smz9QromAccounting.piopOpenings,
      V8Smz9QromAccounting.goldilocksOrder,
      V8Smz9AdaptiveFiniteAccounting.Historical.packingFactor,
      Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
      Hegemon.Transaction.Poseidon2V8ConstraintRefinement.relationConstraintDegree,
      Hegemon.Transaction.Poseidon2Width16Kernel.fieldModulus,
      Hegemon.Transaction.NoteCommitmentInputs.fieldModulus,
      List.range, List.range.loop, List.foldl,
      matrixError]
  rw [matrix_loss_eq_ledger]
  simp only [roleLoss, goldilocks_card]
  calc
    ((1 : Rat) / 18446744069414584321) ^ 5 + epsilon3 + q38LvcsLoss ≤
        ((1 : Rat) / 18446744069414584321) ^ 5 + epsilon3 +
          12 * ((405 : Rat) / 8388571) ^ 38 := by linarith
    _ ≤ matrixError := arithmetic

/-- All four actual local densities fit a conservative factor-two MCA
envelope.  The transported ledger therefore charges `48*T^2` below. -/
theorem four_role_local_loss_le_two_mca_envelope :
    fourRoleLocalLoss ≤
      2 * (matrixError + (1 / 128 : Rat) ^ 38) := by
  have mca : matrixLoss + smallSupportLoss ≤
      matrixError + (1 / 128 : Rat) ^ 38 :=
    add_le_add (le_of_eq matrix_loss_eq_ledger) small_support_loss_le
  have other := non_mca_role_losses_le_matrix_loss
  unfold fourRoleLocalLoss sourceOnlyRoleLoss
  calc
    matrixLoss + roleLoss .piopMatrix + roleLoss .piopOpening +
          (smallSupportLoss + roleLoss .decsSample) =
        (matrixLoss + smallSupportLoss) +
          (roleLoss .piopMatrix + roleLoss .piopOpening + roleLoss .decsSample) := by
      ring
    _ ≤ (matrixError + (1 / 128 : Rat) ^ 38) + matrixLoss :=
      add_le_add mca other
    _ ≤ 2 * (matrixError + (1 / 128 : Rat) ^ 38) := by
      rw [matrix_loss_eq_ledger]
      have sampleNonnegative : 0 ≤ (1 / 128 : Rat) ^ 38 := by positivity
      linarith

/-- Every concrete role density is nonnegative. -/
theorem source_only_role_loss_nonnegative (role : Role) :
    0 ≤ sourceOnlyRoleLoss role := by
  cases role <;>
    dsimp only [sourceOnlyRoleLoss, roleLoss, matrixLoss, smallSupportLoss,
      q38LvcsLoss, q38SingleRootLoss, epsilon3] <;> positivity

/-- Instability used by the exact conditioned-role CMS endpoint. -/
def roleInstability (T : Nat) (role : Role) : Rat :=
  (3 * (T : Rat)) / (2 : Rat) ^ 512 + sourceOnlyRoleLoss role

theorem role_instability_nonnegative (T : Nat) (role : Role) :
    0 ≤ roleInstability T role := by
  unfold roleInstability
  exact add_nonneg (by positivity) (source_only_role_loss_nonnegative role)

/-- One exact `oracleLoss` expression delivered by
`conditioned_role_oracle_failure_bound`. -/
def conditionedRoleOracleLoss
    (T claimBudget outputCardinality : Nat) (role : Role) : ℝ :=
  oracleLoss
    (databaseLoss T ((roleInstability T role : Rat) : ℝ))
    ((((claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ))

/-- The exact sum of all four conditioned-role losses, before initialized
event transport. -/
def fourRoleOracleLoss (T claimBudget outputCardinality : Nat) : ℝ :=
  conditionedRoleOracleLoss T claimBudget outputCardinality .decsMatrix +
    conditionedRoleOracleLoss T claimBudget outputCardinality .piopMatrix +
    conditionedRoleOracleLoss T claimBudget outputCardinality .piopOpening +
    conditionedRoleOracleLoss T claimBudget outputCardinality .decsSample

/-- Apply the checked square-root elimination to each exact conditioned-role
CMS loss.  The `144*T^3` term and the claim bridge are visible rather than
being silently charged to initialized coupling. -/
theorem four_role_oracle_loss_le_rational_sum
    (T claimBudget outputCardinality : Nat)
    (outputPositive : 0 < outputCardinality) :
    fourRoleOracleLoss T claimBudget outputCardinality ≤
      (((12 * (T : Rat) ^ 2 * fourRoleLocalLoss +
          144 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 +
          8 * (claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) := by
  have perRole (role : Role) :
      conditionedRoleOracleLoss T claimBudget outputCardinality role ≤
        (((12 * (T : Rat) ^ 2 * roleInstability T role +
            2 * (claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) := by
    have databaseNonnegative :
        0 ≤ databaseLoss T ((roleInstability T role : Rat) : ℝ) :=
      database_loss_nonnegative T (by
        exact_mod_cast role_instability_nonnegative T role)
    have bridgeNonnegative :
        0 ≤ ((((claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) := by
      positivity
    unfold conditionedRoleOracleLoss
    calc
      _ ≤ 2 * databaseLoss T ((roleInstability T role : Rat) : ℝ) +
            2 * ((((claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) :=
        oracle_loss_le_two_sum _ _ databaseNonnegative bridgeNonnegative
      _ = _ := by
        unfold databaseLoss
        push_cast
        ring
  unfold fourRoleOracleLoss
  calc
    _ ≤
        (((12 * (T : Rat) ^ 2 * roleInstability T .decsMatrix +
            2 * (claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) +
        (((12 * (T : Rat) ^ 2 * roleInstability T .piopMatrix +
            2 * (claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) +
        (((12 * (T : Rat) ^ 2 * roleInstability T .piopOpening +
            2 * (claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) +
        (((12 * (T : Rat) ^ 2 * roleInstability T .decsSample +
            2 * (claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) := by
      exact add_le_add
        (add_le_add
          (add_le_add (perRole .decsMatrix) (perRole .piopMatrix))
          (perRole .piopOpening))
        (perRole .decsSample)
    _ = _ := by
      unfold roleInstability fourRoleLocalLoss
      push_cast
      ring

/-- Add the four initialized event-transport coupling masses exactly once.
The factor two is the conservative square-root event transport, and the four
roles give `2 * 4 * 576 = 8 * 576`. -/
def transportedFourRoleLoss (T claimBudget outputCardinality : Nat) : ℝ :=
  2 * fourRoleOracleLoss T claimBudget outputCardinality +
    (((8 * 576 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 : Rat) : ℝ))

/-- Exact rational upper bound corresponding to the transported four-role
oracle sum. -/
def fourRoleStageUpper (T claimBudget outputCardinality : Nat) : Rat :=
  24 * (T : Rat) ^ 2 * fourRoleLocalLoss +
    288 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 +
    16 * (claimBudget : Rat) ^ 2 / outputCardinality +
    8 * 576 * (T : Rat) ^ 3 / (2 : Rat) ^ 512

theorem transported_four_role_loss_le_stage_upper
    (T claimBudget outputCardinality : Nat)
    (outputPositive : 0 < outputCardinality) :
    transportedFourRoleLoss T claimBudget outputCardinality ≤
      ((fourRoleStageUpper T claimBudget outputCardinality : Rat) : ℝ) := by
  have oracle := four_role_oracle_loss_le_rational_sum
    T claimBudget outputCardinality outputPositive
  unfold transportedFourRoleLoss fourRoleStageUpper
  calc
    _ ≤ 2 *
        (((12 * (T : Rat) ^ 2 * fourRoleLocalLoss +
          144 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 +
          8 * (claimBudget : Rat) ^ 2 / outputCardinality : Rat) : ℝ)) +
        (((8 * 576 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 : Rat) : ℝ)) := by
      exact add_le_add (mul_le_mul_of_nonneg_left oracle (by norm_num)) le_rfl
    _ = _ := by
      push_cast
      ring

/-- Fully conservative cap after separately adding CMS instability, the claim
bridge, and all four initialized coupling charges. -/
def cappedFourRoleStageBudget : Rat :=
  48 * (3 * (2 : Rat) ^ 64) ^ 2 *
      (matrixError + (1 / 128 : Rat) ^ 38) +
    4912 * (3 * (2 : Rat) ^ 64) ^ 3 / (2 : Rat) ^ 512

/-- The four transported claim bridges retain their own 512-bit charge. -/
theorem claim_bridges_le_512_bit_bridge
    (T claimBudget outputCardinality : Nat)
    (claims : claimBudget ≤ T)
    (output : 2 ^ 512 ≤ outputCardinality) :
    16 * (claimBudget : Rat) ^ 2 / outputCardinality ≤
      16 * (T : Rat) ^ 2 / (2 : Rat) ^ 512 := by
  have claimSquare : (claimBudget : Rat) ^ 2 ≤ (T : Rat) ^ 2 := by
    gcongr
  have outputPositive : (0 : Rat) < outputCardinality := by
    exact_mod_cast (lt_of_lt_of_le (by positivity : 0 < 2 ^ 512) output)
  have denominator :
      (claimBudget : Rat) ^ 2 / outputCardinality ≤
        (T : Rat) ^ 2 / (2 : Rat) ^ 512 := by
    apply (div_le_div_iff₀ outputPositive (by positivity)).2
    calc
      (claimBudget : Rat) ^ 2 * (2 : Rat) ^ 512 ≤
          (T : Rat) ^ 2 * (2 : Rat) ^ 512 :=
        mul_le_mul_of_nonneg_right claimSquare (by positivity)
      _ ≤ (T : Rat) ^ 2 * outputCardinality := by
        apply mul_le_mul_of_nonneg_left _ (sq_nonneg (T : Rat))
        exact_mod_cast output
  calc
    16 * (claimBudget : Rat) ^ 2 / outputCardinality =
        16 * ((claimBudget : Rat) ^ 2 / outputCardinality) := by ring
    _ ≤ 16 * ((T : Rat) ^ 2 / (2 : Rat) ^ 512) := by gcongr
    _ = 16 * (T : Rat) ^ 2 / (2 : Rat) ^ 512 := by ring

/-- Substitute the lifetime/query cap, claim cap, and one retained 512-bit
vector coordinate into the exact rational stage upper bound. -/
theorem four_role_stage_upper_le_capped
    (T claimBudget outputCardinality : Nat)
    (positive : 1 ≤ T)
    (queries : T ≤ 3 * 2 ^ 64)
    (claims : claimBudget ≤ T)
    (output : 2 ^ 512 ≤ outputCardinality) :
    fourRoleStageUpper T claimBudget outputCardinality ≤
      cappedFourRoleStageBudget := by
  have queryRat : (T : Rat) ≤ 3 * (2 : Rat) ^ 64 := by exact_mod_cast queries
  have querySquare : (T : Rat) ^ 2 ≤ (3 * (2 : Rat) ^ 64) ^ 2 := by gcongr
  have queryCube : (T : Rat) ^ 3 ≤ (3 * (2 : Rat) ^ 64) ^ 3 := by gcongr
  have localBound := four_role_local_loss_le_two_mca_envelope
  have localTerm :
      24 * (T : Rat) ^ 2 * fourRoleLocalLoss ≤
        48 * (3 * (2 : Rat) ^ 64) ^ 2 *
          (matrixError + (1 / 128 : Rat) ^ 38) := by
    have envelopeNonnegative :
        0 ≤ matrixError + (1 / 128 : Rat) ^ 38 := by
      unfold matrixError
      positivity
    calc
      _ ≤ 24 * (T : Rat) ^ 2 *
          (2 * (matrixError + (1 / 128 : Rat) ^ 38)) :=
        mul_le_mul_of_nonneg_left localBound (by positivity)
      _ ≤ 24 * (3 * (2 : Rat) ^ 64) ^ 2 *
          (2 * (matrixError + (1 / 128 : Rat) ^ 38)) := by
        apply mul_le_mul_of_nonneg_right _ (mul_nonneg (by norm_num) envelopeNonnegative)
        exact mul_le_mul_of_nonneg_left querySquare (by norm_num)
      _ = _ := by ring
  have bridge := claim_bridges_le_512_bit_bridge
    T claimBudget outputCardinality claims output
  have tOne : (1 : Rat) ≤ T := by exact_mod_cast positive
  have squareLeCube : (T : Rat) ^ 2 ≤ (T : Rat) ^ 3 := by
    have productNonnegative :
        0 ≤ (T : Rat) ^ 2 * ((T : Rat) - 1) :=
      mul_nonneg (sq_nonneg (T : Rat)) (sub_nonneg.mpr tOne)
    nlinarith [productNonnegative]
  unfold fourRoleStageUpper cappedFourRoleStageBudget
  have tail :
      288 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 +
          16 * (claimBudget : Rat) ^ 2 / outputCardinality +
          8 * 576 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 ≤
        4912 * (3 * (2 : Rat) ^ 64) ^ 3 / (2 : Rat) ^ 512 := by
    calc
      _ ≤ 288 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 +
          16 * (T : Rat) ^ 2 / (2 : Rat) ^ 512 +
          8 * 576 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 :=
        add_le_add (add_le_add le_rfl bridge) le_rfl
      _ = (4896 * (T : Rat) ^ 3 + 16 * (T : Rat) ^ 2) /
          (2 : Rat) ^ 512 := by ring
      _ ≤ 4912 * (T : Rat) ^ 3 / (2 : Rat) ^ 512 := by
        apply div_le_div_of_nonneg_right _ (by positivity)
        nlinarith
      _ ≤ _ := by
        apply div_le_div_of_nonneg_right _ (by positivity)
        exact mul_le_mul_of_nonneg_left queryCube (by norm_num)
  linarith

/-- Pure numerical endpoint.  It proves a strict 128-bit bound for the
four-role stage ledger only; no accepted-execution, binding, semantic, or
lifetime event is asserted here. -/
theorem capped_four_role_stage_budget_below_128_bits :
    cappedFourRoleStageBudget < (1 / 2 : Rat) ^ 128 := by
  norm_num [cappedFourRoleStageBudget, matrixError]

/-- The complete stage accounting consumes less than half the 128-bit target.
The remaining half is explicit headroom, not an assertion that binding or
lifetime reductions have been supplied. -/
def bindingLifetimeHeadroom : Rat :=
  (1 / 2 : Rat) ^ 128 - cappedFourRoleStageBudget

theorem capped_four_role_stage_budget_below_129_bits :
    cappedFourRoleStageBudget < (1 / 2 : Rat) ^ 129 := by
  norm_num [cappedFourRoleStageBudget, matrixError]

theorem binding_lifetime_headroom_exceeds_half_target :
    (1 / 2 : Rat) ^ 129 < bindingLifetimeHeadroom := by
  have stage := capped_four_role_stage_budget_below_129_bits
  unfold bindingLifetimeHeadroom
  have target : (1 / 2 : Rat) ^ 128 = 2 * (1 / 2 : Rat) ^ 129 := by norm_num
  linarith

/-- Any separately proved binding/lifetime ledger strictly inside the exposed
headroom composes with the stage budget below the 128-bit target. -/
theorem stage_plus_binding_lifetime_below_128_bits
    (bindingLifetimeLoss : Rat)
    (within : bindingLifetimeLoss < bindingLifetimeHeadroom) :
    cappedFourRoleStageBudget + bindingLifetimeLoss < (1 / 2 : Rat) ^ 128 := by
  unfold bindingLifetimeHeadroom at within
  linarith

end
end HegemonCrypto.SmallWood.SmzaRp04FourRoleLedger
