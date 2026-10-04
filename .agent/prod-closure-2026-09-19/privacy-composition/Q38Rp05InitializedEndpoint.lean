import Q38Rp05AdaptiveEndpoint
import Q38Rp05PrefinalBudget

/-! Specialization to the literal zero-entry initialized random oracle.
Neither CMS support nor initial mass is left as an external premise. -/
namespace HegemonCrypto.SmallWood.Q38Rp05InitializedEndpoint

open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.Q38Rp05ActualPivot
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveEndpoint
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 1000000
attribute [local irreducible] uniformAverage
variable {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
local notation "OracleInput" => Rp05FullRawInput bound
local notation "W" => Unit × Work

def initializedCms
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    ResponseCmsState OracleInput W :=
  partialRandomOracleState (Output := DigestRegister) ∅ (responseFourierRegisters registers)

theorem initialized_cms_bounded
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    BoundedState 0 (initializedCms registers) :=
  partial_random_oracle_empty_bounded _

theorem initialized_cms_total
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    TotalDatabaseSupport (phaseDecode (initializedCms registers)) := by
  rw [initializedCms, phase_decode_empty_fourier_initial]
  exact total_oracle_family_has_total_database_support _

theorem initialized_cms_mass
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    normSquared (initializedCms registers) = ‖WithLp.toLp 2 registers‖ ^ 2 := by
  rw [← phase_decode_norm_squared, initializedCms, phase_decode_empty_fourier_initial,
    total_oracle_family_norm_squared]
  simpa only [familyGameState] using
    (uniform_average_const (A := OracleInput → DigestRegister)
      (‖WithLp.toLp 2 registers‖ ^ 2))

theorem initialized_phase_is_acceptance (program : Program OracleInput W)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    phaseRun true program (initializedCms registers) =
      acceptance true program (WithLp.toLp 2 registers) := by
  rw [phase_run_eq_database_run, initializedCms, phase_decode_empty_fourier_initial]
  exact databaseRun_initialized_family_eq_acceptance true program (WithLp.toLp 2 registers)

/-- Literal capped CMS interpreter, not just its abstract phase conjugate. -/
theorem initialized_actual_cms_is_acceptance {requests : Nat}
    (schedule : Schedule bound W requests) (total real : Nat)
    (budget : WithinBudget schedule total) (index : real ≤ requests)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    actualPhaseRun total true (compiledHybrid real schedule) (initializedCms registers) =
      acceptance true (compiledHybrid real schedule) (WithLp.toLp 2 registers) :=
  actual_phase_run_initialized_acceptance total true (compiledHybrid real schedule)
    registers (compiled_hybrid_within_budget schedule total real budget index)

/-- Whole-view real/public acceptance, from a fixed response-basis register
state chosen before the one uniform oracle draw. Its mass remains explicit. -/
theorem initialized_adaptive_acceptance_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    {requests : Nat} (schedule : Schedule bound W requests)
    (eligible : Eligible components nonlinearRoot nodeDegree schedule)
    (total : Nat) (budget : WithinBudget schedule total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ) :
    |acceptance true (compiledHybrid requests schedule) (WithLp.toLp 2 registers) -
      acceptance true (compiledHybrid 0 schedule) (WithLp.toLp 2 registers)| ≤
      (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) * loss total *
        ‖WithLp.toLp 2 registers‖ ^ 2 := by
  have result := actual_adaptive_real_public_bound components nonlinearRoot nodeDegree certificates
    abortPoints abortAdmissible abortNonzero abortTargets schedule eligible total budget
    (initializedCms registers) (initialized_cms_bounded registers) (initialized_cms_total registers)
  simpa only [initialized_phase_is_acceptance, initialized_cms_mass] using result

theorem normalized_adaptive_acceptance_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    {requests : Nat} (schedule : Schedule bound W requests)
    (eligible : Eligible components nonlinearRoot nodeDegree schedule)
    (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount (hybrid requests schedule) ≤ total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister) (Workspace := W) → ℂ)
    (normalized : ‖WithLp.toLp 2 registers‖ = 1) :
    |acceptance true (compiledHybrid requests schedule) (WithLp.toLp 2 registers) -
      acceptance true (compiledHybrid 0 schedule) (WithLp.toLp 2 registers)| ≤
      (Q38Rp05ReachableBudget.effectiveRequests requests total : ℝ) * loss total := by
  simpa only [normalized, one_pow, mul_one] using initialized_adaptive_acceptance_bound
    components nonlinearRoot nodeDegree certificates abortPoints abortAdmissible abortNonzero
    abortTargets schedule eligible total
    (Q38Rp05PrefinalBudget.within_budget_of_all_real schedule total budget) registers

end
end HegemonCrypto.SmallWood.Q38Rp05InitializedEndpoint
