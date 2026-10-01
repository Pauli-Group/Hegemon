import Q38Rp05CurrentFreshBound

/-!
# Homogeneous RP05 FRESH bound

This module keeps the incoming Born mass in both factors of the continuity
argument. It does not normalize histories. A zero-mass history contributes
zero, and summing orthogonal histories introduces no outcome-count factor.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentFreshMassBound

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical ENNReal

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

section Continuity
variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

/-- Continuity on arbitrary unnormalized total-oracle families. The first
factor retains the common incoming mass instead of replacing it by one. -/
theorem database_run_total_family_difference_mass
    (randomized : Bool) (program : Program Input Work)
    (left right : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (mass : ℝ)
    (leftMass : normSquared (totalOracleFamilyState left) ≤ mass)
    (rightMass : normSquared (totalOracleFamilyState right) ≤ mass) :
    |databaseRun randomized program (totalOracleFamilyState left) -
      databaseRun randomized program (totalOracleFamilyState right)| ≤
      Real.sqrt (4 * mass) * Real.sqrt (normSquared
        (totalOracleFamilyState left - totalOracleFamilyState right)) := by
  rw [databaseRun_totalOracleFamilyState, databaseRun_totalOracleFamilyState]
  apply (average_difference_abs_le _ _).trans
  have pointwise (oracle : Input → DigestRegister) :
      |databaseRun randomized program
          (oracleState oracle (familyGameState left oracle)) -
        databaseRun randomized program
          (oracleState oracle (familyGameState right oracle))| ≤
      (‖familyGameState left oracle‖ + ‖familyGameState right oracle‖) *
        ‖familyGameState left oracle - familyGameState right oracle‖ := by
    rw [databaseRun_oracleState, databaseRun_oracleState]
    exact run_difference_subnormalized randomized program oracle
      (familyGameState left oracle) (familyGameState right oracle)
  apply (average_mono _ _ pointwise).trans
  apply (uniform_average_mul_le_sqrt_mul_sqrt
    (fun oracle : Input → DigestRegister =>
      ‖familyGameState left oracle‖ + ‖familyGameState right oracle‖)
    (fun oracle : Input → DigestRegister =>
      ‖familyGameState left oracle - familyGameState right oracle‖)).trans
  have firstMoment : uniformAverage (fun oracle : Input → DigestRegister =>
      (‖familyGameState left oracle‖ + ‖familyGameState right oracle‖)^2) ≤
      4 * mass := by
    calc
      _ ≤ uniformAverage (fun oracle : Input → DigestRegister =>
          2 * ‖familyGameState left oracle‖^2 +
            2 * ‖familyGameState right oracle‖^2) := by
        apply average_mono
        intro oracle
        nlinarith [sq_nonneg
          (‖familyGameState left oracle‖ - ‖familyGameState right oracle‖)]
      _ = 2 * normSquared (totalOracleFamilyState left) +
          2 * normSquared (totalOracleFamilyState right) := by
        rw [average_add, average_mul_left, average_mul_left,
          ← total_oracle_family_norm_squared,
          ← total_oracle_family_norm_squared]
      _ ≤ 4 * mass := by linarith
  rw [← total_oracle_family_difference_norm_squared]
  exact mul_le_mul_of_nonneg_right (Real.sqrt_le_sqrt firstMoment)
    (Real.sqrt_nonneg _)

/-- The diagonal continuation keeps the same tape in its state and program.
Mass appears quadratically: sqrt(mass) from continuity and sqrt(mass) from
the averaged disturbance. This gives delta * mass, including mass zero. -/
theorem phase_run_total_support_dependent_mass
    {Secret : Type} [Fintype Secret] [Nonempty Secret]
    (randomized : Bool) (program : Secret → Program Input Work)
    (left : Secret → ResponseCmsState Input Work)
    (right : ResponseCmsState Input Work)
    (leftSupport : ∀ secret, TotalDatabaseSupport (phaseDecode (left secret)))
    (rightSupport : TotalDatabaseSupport (phaseDecode right))
    (mass loss : ℝ) (massNonnegative : 0 ≤ mass) (lossNonnegative : 0 ≤ loss)
    (leftMass : ∀ secret, normSquared (phaseDecode (left secret)) ≤ mass)
    (rightMass : normSquared (phaseDecode right) ≤ mass)
    (meanSquare : uniformAverage (fun secret =>
      normSquared (phaseDecode (left secret) - phaseDecode right)) ≤
        loss * mass) :
    |uniformAverage (fun secret => phaseRun randomized (program secret)
        (left secret)) -
      uniformAverage (fun secret => phaseRun randomized (program secret)
        right)| ≤ (2 * Real.sqrt loss) * mass := by
  apply (average_difference_abs_le _ _).trans
  have pointwise (secret : Secret) :
      |phaseRun randomized (program secret) (left secret) -
        phaseRun randomized (program secret) right| ≤
      Real.sqrt (4 * mass) * Real.sqrt
        (normSquared (phaseDecode (left secret) - phaseDecode right)) := by
    rw [phase_run_eq_database_run, phase_run_eq_database_run]
    have comparison := database_run_total_family_difference_mass randomized
      (program secret) (canonicalTotalFamily (phaseDecode (left secret)))
      (canonicalTotalFamily (phaseDecode right)) mass
      (by rw [total_oracle_family_canonical_eq _ (leftSupport secret)]
          exact leftMass secret)
      (by rw [total_oracle_family_canonical_eq _ rightSupport]
          exact rightMass)
    simpa only [total_oracle_family_canonical_eq _ (leftSupport secret),
      total_oracle_family_canonical_eq _ rightSupport] using comparison
  apply (average_mono _ _ pointwise).trans
  rw [average_mul_left]
  have nonnegative (secret : Secret) :
      0 ≤ normSquared (phaseDecode (left secret) - phaseDecode right) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have averaged := uniform_average_le_sqrt_mean_square
    (fun secret => Real.sqrt
      (normSquared (phaseDecode (left secret) - phaseDecode right)))
    (fun _ => Real.sqrt_nonneg _) (loss * mass)
    (mul_nonneg lossNonnegative massNonnegative)
    (by simpa only [Real.sq_sqrt (nonnegative _)] using meanSquare)
  apply (mul_le_mul_of_nonneg_left averaged (Real.sqrt_nonneg _)).trans_eq
  rw [Real.sqrt_mul (by norm_num : (0 : ℝ) ≤ 4),
    Real.sqrt_mul lossNonnegative]
  have sqrtFour : Real.sqrt (4 : ℝ) = 2 := by
    have square := Real.sqrt_sq_eq_abs (2 : ℝ)
    norm_num at square
    exact square
  rw [sqrtFour]
  calc
    _ = (2 * Real.sqrt loss) * (Real.sqrt mass)^2 := by ring
    _ = _ := by rw [Real.sq_sqrt massNonnegative]

end Continuity

section Rp05Mass
variable {Branch Other Work : Type}
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype Other] [DecidableEq Other]
variable [Fintype Work] [DecidableEq Work]

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "OracleInput" => Rp05LeafInput ⊕ Other
local notation "FullWork" => (LeafIndex → DigestRegister) × (Branch × Work)
local notation "FullCore" =>
  Core OracleInput Branch (OracleInput × DigestRegister × Work) DigestRegister

/-- Branch-controlled RP05 resampling with its exact incoming Born mass.
The statement, salt and payload may depend on the retained public history.
The same arbitrary tape-dependent continuation runs on both sides. No
normalization or local security bound is assumed for any history. -/
theorem rp05_initialized_dependent_phase_run_bound_mass
    (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core))
    (randomized : Bool)
    (program : (LeafIndex → LeafTape) → Program OracleInput FullWork)
    (baseSupport : TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) core))) :
    |uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized (program tapes)
          (controlledCompressed (rp05Selected preamble salt data tapes)
            indices (initializedFreshState core))) -
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun randomized (program tapes)
          (initializedFreshState (Index := LeafIndex) core))| ≤
      (2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)) *
        ∑ basis : FullCore, ‖core basis‖ ^ 2 := by
  let base : ResponseCmsState OracleInput FullWork :=
    initializedFreshState (Index := LeafIndex) core
  let changed : (LeafIndex → LeafTape) → ResponseCmsState OracleInput FullWork :=
    fun tapes => controlledCompressed (rp05Selected preamble salt data tapes)
      indices base
  let mass : ℝ := ∑ basis : FullCore, ‖core basis‖ ^ 2
  have jZero : J (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := Work)
      (Index := LeafIndex) (Branch := Branch)
      (0 : ResponseCmsState OracleInput FullWork) = 0 := by ext basis; rfl
  have baseMass : normSquared (phaseDecode base) = mass := by
    rw [phase_decode_norm_squared]
    have native := J_sub_norm_squared
      (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := Work)
      (Index := LeafIndex) (Branch := Branch)
      base (0 : ResponseCmsState OracleInput FullWork)
    rw [jZero, sub_zero, sub_zero] at native
    rw [show J base = freshLabels (Index := LeafIndex) core by
      exact J_initializedFreshState core, fresh_labels_norm_sq] at native
    exact native.symm
  have changedMass (tapes : LeafIndex → LeafTape) :
      normSquared (phaseDecode (changed tapes)) = mass := by
    rw [phase_decode_norm_squared]
    have native := J_sub_norm_squared
      (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Work := Work)
      (Index := LeafIndex) (Branch := Branch)
      (changed tapes) (0 : ResponseCmsState OracleInput FullWork)
    rw [jZero, sub_zero, sub_zero] at native
    rw [show J (changed tapes) =
        exchangeMany (rp05Selected preamble salt data tapes) indices
          (freshLabels (Index := LeafIndex) core) by
      unfold changed base
      rw [J_controlled_many, J_initializedFreshState]] at native
    rw [(exchangeMany (rp05Selected preamble salt data tapes)
      indices).norm_map, fresh_labels_norm_sq] at native
    exact native.symm
  have changedSupport (tapes : LeafIndex → LeafTape) :
      TotalDatabaseSupport (phaseDecode (changed tapes)) := by
    unfold phaseDecode
    apply total_database_support_response_fourier_inverse
    rw [show globalDecompress (changed tapes) =
        controlledRaw (rp05Selected preamble salt data tapes) indices
          (globalDecompress base) by
      exact global_controlled_swap_intertwining _ _ _]
    exact total_database_support_controlled_raw _ _ _ baseSupport
  have decodedBaseSupport : TotalDatabaseSupport (phaseDecode base) := by
    exact total_database_support_response_fourier_inverse _ baseSupport
  have meanSquare : uniformAverage (fun tapes : LeafIndex → LeafTape =>
      normSquared (phaseDecode (changed tapes) - phaseDecode base)) ≤
      (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) * mass := by
    have native := rp05_initialized_resampling_disturbance
      preamble salt data indices core queries bounded
    have same (tapes : LeafIndex → LeafTape) :
        normSquared (phaseDecode (changed tapes) - phaseDecode base) =
          ‖exchangeMany (rp05Selected preamble salt data tapes) indices
              (freshLabels (Index := LeafIndex) core) - freshLabels core‖^2 := by
      rw [phase_decode_difference_norm_squared]
      rw [← J_sub_norm_squared
        (Input := OracleInput) (Output := DigestRegister)
        (Phase := DigestRegister) (Work := Work)
        (Index := LeafIndex) (Branch := Branch)]
      unfold changed base
      rw [J_controlled_many, J_initializedFreshState]
    simpa only [same] using native
  have massNonnegative : 0 ≤ mass := by
    exact Finset.sum_nonneg fun basis _ => sq_nonneg (‖core basis‖)
  have lossNonnegative :
      0 ≤ 4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
    mul_nonneg (mul_nonneg (by norm_num) (Nat.cast_nonneg queries))
      (inv_nonneg.mpr (pow_nonneg (by norm_num) 512))
  exact phase_run_total_support_dependent_mass
    (Input := OracleInput) (Work := FullWork) (Secret := LeafIndex → LeafTape)
    randomized program changed base
    changedSupport decodedBaseSupport mass
    (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)
    massNonnegative lossNonnegative
    (fun tapes => (changedMass tapes).le) baseMass.le meanSquare

end Rp05Mass
end
end HegemonCrypto.SmallWood.Q38Rp05CurrentFreshMassBound
