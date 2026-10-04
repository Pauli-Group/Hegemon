import Q38Rp05InitializedEndpoint
import Q38Rp05TwoWitnessEndpoint
import Q38Rp05CanonicalAbortPadding
import Q38Rp05PrivacyNumerics
import SmzaRp05Components
import SmzaRp05DegreeCertificateData
import SmzaRp05GeneratedCertificates

/-! A public simulator endpoint for the current RP05 adaptive schedule.
The public schedule is a representative of the public interface; its
per-request witness fields do not affect the simulator program. -/
namespace HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint

open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveEndpoint
open HegemonCrypto.SmallWood.Q38Rp05InitializedEndpoint
open HegemonCrypto.SmallWood.Q38Rp05TwoWitnessEndpoint
open HegemonCrypto.SmallWood.Q38Rp05ReachableBudget
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9MixedMaskCompiler
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 1024

variable {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
local notation "OracleInput" => Rp05FullRawInput bound
local notation "W" => Unit × Work

omit [DecidableEq Work] in
/-- Exact independence of the public simulator from the representative's
private witness fields. `SamePublicStrategy` fixes public operations,
observations, randomness and public request data, but places no equality
condition on witnesses. -/
theorem public_simulator_program_independent_of_witnesses
    {requests : Nat}
    {realSchedule publicSchedule : Schedule bound W requests}
    (same : SamePublicStrategy realSchedule publicSchedule) :
    compiledHybrid 0 realSchedule = compiledHybrid 0 publicSchedule :=
  same_strategy_same_compiled_public same

/-- Current RP05 initialized adaptive zero knowledge against the explicit
witness-free public simulator. `publicSchedule` is only a representative of
the same honest public interface: its witness fields are ignored by the
simulator, as certified by
`public_simulator_program_independent_of_witnesses`. The real schedule alone
must contain accepted current-RP05 witnesses and satisfy the actual query
budget. -/
theorem current_rp05_initialized_real_vs_public_simulator
    {requests : Nat}
    (realSchedule publicSchedule : Schedule bound W requests)
    (same : SamePublicStrategy realSchedule publicSchedule)
    (eligible : Eligible SmzaRp05Components.program
      SmzaRp05DegreeCertificateData.nonlinearRoot
      SmzaRp05DegreeCertificateData.nodeDegree realSchedule)
    (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount
      (hybrid requests realSchedule) ≤ total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister)
      (Workspace := W) → ℂ)
    (normalized : ‖WithLp.toLp 2 registers‖ = 1) :
    |phaseRun true (compiledHybrid requests realSchedule)
        (initializedCms registers) -
      phaseRun true (compiledHybrid 0 publicSchedule)
        (initializedCms registers)| ≤
      (effectiveRequests requests total : ℝ) *
        (2 * Real.sqrt (4 * (total : ℝ) * (2 ^ 512 : ℝ)⁻¹) +
          4 * (total : ℝ) / (2 : ℝ)^256) := by
  have bound := normalized_adaptive_acceptance_bound
    SmzaRp05Components.program
    SmzaRp05DegreeCertificateData.nonlinearRoot
    SmzaRp05DegreeCertificateData.nodeDegree
    SmzaRp05GeneratedCertificates.certificates
    Q38Rp05CanonicalAbortPadding.points
    Q38Rp05CanonicalAbortPadding.points_admissible
    Q38Rp05CanonicalAbortPadding.points_nonzero
    Q38Rp05CanonicalAbortPadding.targets
    realSchedule eligible total budget registers normalized
  rw [public_simulator_program_independent_of_witnesses same] at bound
  simpa only [initialized_phase_is_acceptance,
    HegemonCrypto.SmallWood.Q38Rp05ActualPivot.loss] using bound

/-- Rounded concrete loss for the same real-versus-public-simulator endpoint.
The only additional step is the existing effective two-witness numerical
ledger; this adds no security premise or new game argument. -/
theorem current_rp05_initialized_real_vs_public_simulator_loss_bound
    {requests : Nat}
    (realSchedule publicSchedule : Schedule bound W requests)
    (same : SamePublicStrategy realSchedule publicSchedule)
    (eligible : Eligible SmzaRp05Components.program
      SmzaRp05DegreeCertificateData.nonlinearRoot
      SmzaRp05DegreeCertificateData.nodeDegree realSchedule)
    (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount
      (hybrid requests realSchedule) ≤ total)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister)
      (Workspace := W) → ℂ)
    (normalized : ‖WithLp.toLp 2 registers‖ = 1) :
    |phaseRun true (compiledHybrid requests realSchedule)
        (initializedCms registers) -
      phaseRun true (compiledHybrid 0 publicSchedule)
        (initializedCms registers)| ≤
      12 * (total : ℝ)^2 / (2 : ℝ)^279 := by
  have exactBound := current_rp05_initialized_real_vs_public_simulator
    realSchedule publicSchedule same eligible total budget registers normalized
  have exactBound' :
      |phaseRun true (compiledHybrid requests realSchedule) (initializedCms registers) -
        phaseRun true (compiledHybrid 0 publicSchedule) (initializedCms registers)| ≤
        (effectiveRequests requests total : ℝ) *
          HegemonCrypto.SmallWood.Q38Rp05ActualPivot.loss total := by
    simpa only [HegemonCrypto.SmallWood.Q38Rp05ActualPivot.loss] using exactBound
  have numeric :=
    HegemonCrypto.SmallWood.Q38Rp05PrivacyNumerics.effective_two_witness_spec_ledger
      total requests
  have halfNumeric :
      (effectiveRequests requests total : ℝ) *
          HegemonCrypto.SmallWood.Q38Rp05ActualPivot.loss total ≤
        12 * (total : ℝ)^2 / (2 : ℝ)^279 := by
    calc
      (effectiveRequests requests total : ℝ) *
          HegemonCrypto.SmallWood.Q38Rp05ActualPivot.loss total =
        (1 / 2 : ℝ) *
          (2 * (effectiveRequests requests total : ℝ) *
            HegemonCrypto.SmallWood.Q38Rp05ActualPivot.loss total) := by ring
      _ ≤ (1 / 2 : ℝ) * (24 * (total : ℝ)^2 / (2 : ℝ)^279) :=
        mul_le_mul_of_nonneg_left numeric (by norm_num)
      _ = 12 * (total : ℝ)^2 / (2 : ℝ)^279 := by ring
  exact exactBound'.trans halfNumeric

/-- Lifetime-cap specialization of the rounded public endpoint. The bound
`total ≤ 3 * 2^64` is a caller-supplied resource cap, not a security premise. -/
theorem current_rp05_initialized_real_vs_public_simulator_lifetime_cap
    {requests : Nat}
    (realSchedule publicSchedule : Schedule bound W requests)
    (same : SamePublicStrategy realSchedule publicSchedule)
    (eligible : Eligible SmzaRp05Components.program
      SmzaRp05DegreeCertificateData.nonlinearRoot
      SmzaRp05DegreeCertificateData.nodeDegree realSchedule)
    (total : Nat)
    (budget : V8Smz9MixedMaskCompiler.queryCount
      (hybrid requests realSchedule) ≤ total)
    (lifetimeCap : total ≤ 3 * 2^64)
    (registers : RegisterBasis (Input := OracleInput) (Phase := DigestRegister)
      (Workspace := W) → ℂ)
    (normalized : ‖WithLp.toLp 2 registers‖ = 1) :
    |phaseRun true (compiledHybrid requests realSchedule)
        (initializedCms registers) -
      phaseRun true (compiledHybrid 0 publicSchedule)
        (initializedCms registers)| ≤
      (27 / 64 : ℝ) * (2 : ℝ)^(-143 : ℤ) := by
  have rounded := current_rp05_initialized_real_vs_public_simulator_loss_bound
    realSchedule publicSchedule same eligible total budget registers normalized
  have totalLe : (total : ℝ) ≤ ((3 * 2^64 : Nat) : ℝ) := by
    exact_mod_cast lifetimeCap
  have totalNonneg : (0 : ℝ) ≤ (total : ℝ) := Nat.cast_nonneg _
  have capNonneg : (0 : ℝ) ≤ ((3 * 2^64 : Nat) : ℝ) := by positivity
  have squareLe : (total : ℝ)^2 ≤ ((3 * 2^64 : Nat) : ℝ)^2 := by
    have productNonneg := mul_nonneg
      (sub_nonneg.mpr totalLe) (add_nonneg totalNonneg capNonneg)
    nlinarith [productNonneg]
  calc
    _ ≤ 12 * (total : ℝ)^2 / (2 : ℝ)^279 := rounded
    _ ≤ 12 * ((3 * 2^64 : Nat) : ℝ)^2 / (2 : ℝ)^279 := by
      apply div_le_div_of_nonneg_right _ (by positivity)
      exact mul_le_mul_of_nonneg_left squareLe (by norm_num)
    _ = (27 / 64 : ℝ) * (2 : ℝ)^(-143 : ℤ) := by
      calc
        _ = (1 / 2 : ℝ) *
            (24 * ((3 * 2^64 : Nat) : ℝ)^2 / (2 : ℝ)^279) := by ring
        _ = (1 / 2 : ℝ) *
            ((27 / 32 : ℝ) * (2 : ℝ)^(-143 : ℤ)) := by
          rw [HegemonCrypto.SmallWood.Q38Rp05PrivacyNumerics.spec_ledger_at_lifetime_cap]
        _ = _ := by ring

end
end HegemonCrypto.SmallWood.Q38Rp05ZeroKnowledgeEndpoint
