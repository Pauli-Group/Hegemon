import Q38CmsAdaptiveWholeViewApplication

/-!
The full-domain CMS disturbance with a continuation that retains the fresh
tape vector.  This is the diagonal (same tape in the state and continuation)
form required by later selected-opening code.  It changes neither the query
budget nor the `4 * q / 2^512` mean-square loss.

This file does not identify the program family below with the concrete source
request compiler; that separate measured workspace/readout identity remains
an integration obligation.
-/
namespace HegemonCrypto.SmallWood.Q38CmsDependentContinuation

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open scoped BigOperators Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

/-- Continuity for a diagonal family of complete continuations.  The program
may reveal or otherwise use the same secret that indexes the changed state. -/
theorem phase_run_total_support_dependent_hybrid
    {Secret : Type} [Fintype Secret] [Nonempty Secret]
    (randomized : Bool) (program : Secret → Program Input Work)
    (left : Secret → ResponseCmsState Input Work)
    (right : ResponseCmsState Input Work)
    (leftSupport : ∀ secret,
      TotalDatabaseSupport (phaseDecode (left secret)))
    (rightSupport : TotalDatabaseSupport (phaseDecode right))
    (leftSubnormalized : ∀ secret,
      normSquared (phaseDecode (left secret)) ≤ 1)
    (rightSubnormalized : normSquared (phaseDecode right) ≤ 1)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (meanSquare : uniformAverage (fun secret =>
      normSquared
        (phaseDecode (left secret) - phaseDecode right)) ≤ loss) :
    |uniformAverage (fun secret =>
        phaseRun randomized (program secret) (left secret)) -
      uniformAverage (fun secret =>
        phaseRun randomized (program secret) right)| ≤
      2 * Real.sqrt loss := by
  apply (average_difference_abs_le _ _).trans
  have pointwise (secret : Secret) :
      |phaseRun randomized (program secret) (left secret) -
          phaseRun randomized (program secret) right| ≤
        2 * Real.sqrt
          (normSquared
            (phaseDecode (left secret) - phaseDecode right)) := by
    rw [phase_run_eq_database_run, phase_run_eq_database_run]
    rw [show phaseDecode (left secret) =
        totalOracleFamilyState
          (canonicalTotalFamily (phaseDecode (left secret))) by
      exact (total_oracle_family_canonical_eq
        (phaseDecode (left secret)) (leftSupport secret)).symm]
    rw [show phaseDecode right =
        totalOracleFamilyState
          (canonicalTotalFamily (phaseDecode right)) by
      exact (total_oracle_family_canonical_eq
        (phaseDecode right) rightSupport).symm]
    exact database_run_total_family_difference_subnormalized
      randomized (program secret)
      (canonicalTotalFamily (phaseDecode (left secret)))
      (canonicalTotalFamily (phaseDecode right))
      (by
        rw [total_oracle_family_canonical_eq
          (phaseDecode (left secret)) (leftSupport secret)]
        exact leftSubnormalized secret)
      (by
        rw [total_oracle_family_canonical_eq
          (phaseDecode right) rightSupport]
        exact rightSubnormalized)
  apply (average_mono _ _ pointwise).trans
  rw [average_mul_left]
  apply mul_le_mul_of_nonneg_left _ (by norm_num)
  apply uniform_average_le_sqrt_mean_square
    (fun secret => Real.sqrt
      (normSquared (phaseDecode (left secret) - phaseDecode right)))
    (fun _ => Real.sqrt_nonneg _) loss lossNonnegative
  have distanceNonnegative (secret : Secret) :
      0 ≤ normSquared
        (phaseDecode (left secret) - phaseDecode right) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ =>
      Complex.normSq_nonneg
        ((phaseDecode (left secret) - phaseDecode right) basis)
  simpa only [Real.sq_sqrt (distanceNonnegative _)] using meanSquare

section FullDomain

variable {Branch Other BaseWork : Type}
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype Other] [DecidableEq Other]
variable [Fintype BaseWork] [DecidableEq BaseWork]

local notation "FullInput" => LeafInput ⊕ Other
local notation "FullWork" =>
  (LeafIndex → DigestRegister) × (Branch × BaseWork)
local notation "FullCore" =>
  Core FullInput Branch
    (FullInput × DigestRegister × BaseWork) DigestRegister

/-- Concrete q38 form with the tape-dependent continuation kept on both
sides.  In particular, later selected openings may use `tapes` without an
independence assumption. -/
theorem initialized_cms_full_domain_dependent_phase_run_bound
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core))
    (coreSubnormalized : ∑ basis : FullCore, ‖core basis‖ ^ 2 ≤ 1)
    (randomized : Bool)
    (program : (LeafIndex → LeafTape) → Program FullInput FullWork)
    (baseSupport : TotalDatabaseSupport
      (globalDecompress
        (initializedFreshState (Index := LeafIndex) core))) :
    |uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized (program tapes)
          (controlledCompressed (fullPhysicalSelected salt data tapes)
            indices (initializedFreshState core))) -
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized (program tapes)
          (initializedFreshState (Index := LeafIndex) core))| ≤
      2 * Real.sqrt
        (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  let base : ResponseCmsState FullInput FullWork :=
    initializedFreshState (Index := LeafIndex) core
  let changed : (LeafIndex → LeafTape) →
      ResponseCmsState FullInput FullWork :=
    fun tapes => controlledCompressed
      (fullPhysicalSelected salt data tapes) indices base
  have jZero :
      J (Input := FullInput) (Output := DigestRegister)
          (Phase := DigestRegister) (Work := BaseWork)
          (Index := LeafIndex) (Branch := Branch)
          (0 : ResponseCmsState FullInput FullWork) = 0 := by
    ext basis
    rfl
  have baseSubnormalized : normSquared base ≤ 1 := by
    have native := J_sub_norm_squared
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := BaseWork)
      (Index := LeafIndex) (Branch := Branch)
      base (0 : ResponseCmsState FullInput FullWork)
    rw [jZero, sub_zero, sub_zero] at native
    rw [show J base = freshLabels (Index := LeafIndex) core by
      exact J_initializedFreshState core] at native
    rw [fresh_labels_norm_sq] at native
    rw [← native]
    exact coreSubnormalized
  have changedSubnormalized (tapes : LeafIndex → LeafTape) :
      normSquared (changed tapes) ≤ 1 := by
    have native := J_sub_norm_squared
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := BaseWork)
      (Index := LeafIndex) (Branch := Branch)
      (changed tapes) (0 : ResponseCmsState FullInput FullWork)
    rw [jZero, sub_zero, sub_zero] at native
    rw [show J (changed tapes) =
        exchangeMany (fullPhysicalSelected salt data tapes) indices
          (freshLabels (Index := LeafIndex) core) by
      unfold changed base
      rw [J_controlled_many, J_initializedFreshState]] at native
    rw [(exchangeMany (fullPhysicalSelected salt data tapes)
      indices).norm_map, fresh_labels_norm_sq] at native
    rw [← native]
    exact coreSubnormalized
  have decodedBaseSubnormalized : normSquared (phaseDecode base) ≤ 1 := by
    rw [phase_decode_norm_squared]
    exact baseSubnormalized
  have decodedChangedSubnormalized (tapes : LeafIndex → LeafTape) :
      normSquared (phaseDecode (changed tapes)) ≤ 1 := by
    rw [phase_decode_norm_squared]
    exact changedSubnormalized tapes
  have decodedBaseSupport : TotalDatabaseSupport (phaseDecode base) := by
    unfold phaseDecode
    exact total_database_support_response_fourier_inverse
      (globalDecompress base) baseSupport
  have decodedChangedSupport (tapes : LeafIndex → LeafTape) :
      TotalDatabaseSupport (phaseDecode (changed tapes)) := by
    unfold phaseDecode
    apply total_database_support_response_fourier_inverse
    rw [show globalDecompress (changed tapes) =
        controlledRaw (fullPhysicalSelected salt data tapes) indices
          (globalDecompress base) by
      unfold changed
      exact global_controlled_swap_intertwining _ _ _]
    exact total_database_support_controlled_raw
      (fullPhysicalSelected salt data tapes) indices
      (globalDecompress base) baseSupport
  have meanSquare :
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        normSquared
          (phaseDecode (changed tapes) - phaseDecode base)) ≤
        4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
    have native := initialized_cms_full_domain_resampling_disturbance
      (Phase := DigestRegister) (Work := BaseWork)
      (Branch := Branch) (Other := Other)
      salt data indices core queries bounded
    calc
      _ ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ *
          ∑ basis : FullCore, ‖core basis‖ ^ 2 := by
        simpa only [changed, base, phase_decode_difference_norm_squared]
          using native
      _ ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ := by
        simpa only [mul_one] using
          (mul_le_mul_of_nonneg_left coreSubnormalized
            (show 0 ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ by
              positivity))
  exact phase_run_total_support_dependent_hybrid randomized program
    changed base decodedChangedSupport decodedBaseSupport
    decodedChangedSubnormalized decodedBaseSubnormalized
    (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)
    (by positivity) meanSquare

end FullDomain

end
end HegemonCrypto.SmallWood.Q38CmsDependentContinuation
