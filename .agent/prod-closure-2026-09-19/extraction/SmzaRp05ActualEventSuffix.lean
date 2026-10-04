import SmzaRp05ActualEventRecertification
import SmzaRp05AdaptiveRetainedAdviceMass

/-! A recertified event on the same physical prefix and adaptive suffix.
Neither the read interpreter nor its answer-branch weights are replaced. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ActualEventSuffix

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05AdaptiveFilteredCollision SmzaRp05CurrentAdaptiveExecution
open SmzaRp05AdaptivePhysicalReadBound SmzaRp05PhysicalReadTelescope
open SmzaRp05RoleReadTotality SmzaRp05ActualEventRecertification
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

theorem actual_program_suffix_event_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap finish queries depth : Nat) (spec : EventSpec ctx cap)
    (program : ActualProgram ctx cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := Work (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (normalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter → V8SmzaOracleParser.RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    adaptiveReadMass encode decode (SmzaRp05ActualEventRecertification.event spec) suffix
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      6 * (cap : ℝ)^2 * spec.bound := by
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  let compiled := compileProgram ctx cap spec program
  let state := AdaptiveProgram.run compiled initial
  let charge := Real.sqrt (6 * spec.bound)
  have same : state = AdaptiveProgram.run (ActualProgram.compile ctx cap program) initial :=
    compile_program_run_eq ctx cap spec program initial
  have bounded : BoundedState finish state := AdaptiveProgram.run_bounded compiled
    (partial_random_oracle_empty_bounded registers)
  have pre := AdaptiveProgram.amplitude_telescope compiled initial
    (partial_random_oracle_empty_bounded registers) normalized
  change _ ≤ stateNorm (adaptiveProject
      (SmzaRp05ActualEventRecertification.event spec) cap initial) +
      AdaptiveProgram.totalLeak compiled at pre
  rw [initial_projection_zero ctx cap spec registers, state_norm_zero, zero_add,
    compile_program_total_leak] at pre
  rw [← SmzaRp05VectorReadCharge.workspace_event_eq_adaptive_project_of_bounded
    (SmzaRp05ActualEventRecertification.event spec) cap state
    (bounded_state_mono (by omega) bounded)] at pre
  have stateTotal : StandardOn keys state := by simpa only [same, initial] using total
  have amplitude := adaptive_read_role_amplitude_le depth encode decode suffix readBound
    keys keysWithin finish cap state bounded stateTotal supportWithin
    (SmzaRp05ActualEventRecertification.event spec) spec.bound spec.bound_nonnegative
    (fun workspace => spec.instability (ctx.authorizedOf workspace.2))
  have sourceNorm : stateNorm state ≤ 1 := by
    have mass := AdaptiveProgram.run_subnormalized compiled normalized
    simpa using state_norm_le_sqrt state (by norm_num : (0 : ℝ) ≤ 1) mass
  have chargeNonnegative : 0 ≤ charge := Real.sqrt_nonneg _
  have readCharge : (depth : ℝ) * charge * stateNorm state ≤ (depth : ℝ) * charge := by
    nlinarith [mul_le_mul_of_nonneg_left sourceNorm
      (mul_nonneg (Nat.cast_nonneg depth) chargeNonnegative)]
  have count : (queries : ℝ) + depth ≤ cap := by exact_mod_cast queriesWithin
  have totalAmplitude : Real.sqrt
      (adaptiveReadMass encode decode (SmzaRp05ActualEventRecertification.event spec)
        suffix state) ≤ (cap : ℝ) * charge := by
    change _ ≤ _ + (depth : ℝ) * charge * stateNorm state at amplitude
    change stateNorm (workspaceEventProjection
      (SmzaRp05ActualEventRecertification.event spec) state) ≤ (queries : ℝ) * charge at pre
    nlinarith [mul_le_mul_of_nonneg_right count chargeNonnegative]
  have squared := (sq_le_sq₀ (Real.sqrt_nonneg _) (by positivity)).2 totalAmplitude
  rw [Real.sq_sqrt (adaptive_read_mass_nonnegative encode decode
      (SmzaRp05ActualEventRecertification.event spec) suffix state),
    mul_pow, show charge^2 = 6 * spec.bound from
      Real.sq_sqrt (mul_nonneg (by norm_num) spec.bound_nonnegative)] at squared
  rw [same] at squared
  nlinarith only [squared]

end
end HegemonCrypto.SmallWood.SmzaRp05ActualEventSuffix
