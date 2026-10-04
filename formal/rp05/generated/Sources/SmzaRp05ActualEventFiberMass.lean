import SmzaRp05ActualEventSuffix
import SmzaRp05HomogeneousFiberSum
import SmzaRp05HomogeneousExecution

/-! Lift an event-specific adaptive-suffix bound through normalization and the
literal fixed-table disintegration. Every physical answer branch and every
zero-mass fiber keeps its original Born weight. -/
namespace HegemonCrypto.SmallWood.SmzaRp05ActualEventFiberMass

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05AdaptiveFilteredCollision
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05ConditionedExecution
open SmzaRp05HomogeneousFiberSum
open SmzaRp05AdaptiveRetainedAdviceMass
open SmzaRp05AdaptivePhysicalReadBound
open SmzaRp05RoleReadTotality
open SmzaRp05HomogeneousExecution
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

theorem actual_program_suffix_event_mass_le_homogeneous
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap finish queries depth : Nat)
    (spec : SmzaRp05ActualEventRecertification.EventSpec ctx cap)
    (program : ActualProgram ctx cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → VectorOutput Counter →
      V8SmzaOracleParser.RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    adaptiveReadMass encode decode
      (SmzaRp05ActualEventRecertification.event spec) suffix
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      (6 * (cap : ℝ)^2 * spec.bound) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  let mass := normSquared initial
  have massNonnegative : 0 ≤ mass := by
    unfold mass normSquared
    exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _
  by_cases zeroMass : mass = 0
  · have initialZero : initial = 0 := norm_squared_zero_implies_state_zero initial zeroMass
    have explicitInitialZero :
        partialRandomOracleState (Output := VectorOutput Counter) ∅ registers = 0 := by
      simpa [initial] using initialZero
    have runZero : AdaptiveProgram.run (ActualProgram.compile ctx cap program) 0 = 0 := by
      simpa using actual_run_smul ctx cap program 0 initial
    have suffixZero : adaptiveReadMass encode decode
        (SmzaRp05ActualEventRecertification.event spec) suffix
        (0 : SmzaRp05CurrentAdaptiveExecution.CmsState
          (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) = 0 := by
      simpa using adaptive_read_mass_smul encode decode
        (SmzaRp05ActualEventRecertification.event spec) suffix 0 initial
    change _ ≤ (6 * (cap : ℝ)^2 * spec.bound) * mass
    rw [explicitInitialZero, runZero, suffixZero, zeroMass, mul_zero]
  · have positiveMass : 0 < mass := lt_of_le_of_ne massNonnegative (Ne.symm zeroMass)
    let scale : ℂ := ((Real.sqrt mass)⁻¹ : ℝ)
    have scaleMass : Complex.normSq scale * mass = 1 := by
      have square := Real.sq_sqrt massNonnegative
      have nonzero : Real.sqrt mass ≠ 0 := ne_of_gt (Real.sqrt_pos.mpr positiveMass)
      simp only [scale, Complex.normSq_ofReal]
      field_simp [nonzero]
      nlinarith
    have normalized : Subnormalized
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ (scale • registers)) := by
      rw [partial_random_oracle_state_smul, Subnormalized, norm_squared_smul]
      exact le_of_eq scaleMass
    have scaledTotal : StandardOn keys
        (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ (scale • registers))) := by
      rw [partial_random_oracle_state_smul, actual_run_smul]
      intro key member basis absent
      rw [global_decompress_smul]
      change scale * _ = 0
      rw [total key member basis absent, mul_zero]
    have unitBound := SmzaRp05ActualEventSuffix.actual_program_suffix_event_mass_le
      ctx cap finish queries depth spec
      program (scale • registers) normalized encode decode suffix readBound keys keysWithin
      supportWithin queriesWithin scaledTotal
    rw [partial_random_oracle_state_smul, actual_run_smul,
      adaptive_read_mass_smul] at unitBound
    have weighted := mul_le_mul_of_nonneg_right unitBound massNonnegative
    change _ ≤ (6 * (cap : ℝ)^2 * spec.bound) * mass
    calc
      _ = (Complex.normSq scale *
          adaptiveReadMass encode decode
            (SmzaRp05ActualEventRecertification.event spec) suffix
            (AdaptiveProgram.run (ActualProgram.compile ctx cap program) initial)) * mass := by
        rw [mul_right_comm, scaleMass, one_mul]
      _ ≤ _ := weighted

/-- Sum the event-specific suffix bound across the actual fixed tables. The
same numerical loss is charged once because the initial fiber masses sum to
the original incoming mass. -/
theorem sum_fixed_actual_event_suffix_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (cap finish queries depth : Nat)
    (spec : ∀ fixed : FixedTable ctx blockCap,
      SmzaRp05ActualEventRecertification.EventSpec
        (activeContext ctx blockCap fixed) cap)
    (commonBound : ℝ) (sameBound : ∀ fixed, (spec fixed).bound = commonBound)
    (program : ∀ fixed : FixedTable ctx blockCap,
      ActualProgram (activeContext ctx blockCap fixed) cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : V8SmzaOracleParser.RawInput →
      ActiveKey ctx.role blockCap ctx.keyBytes)
    (decode : FixedTable ctx blockCap → V8SmzaOracleParser.RawInput →
      VectorOutput Counter → V8SmzaOracleParser.RawDigest)
    (suffix : FixedTable ctx blockCap → Program Result)
    (readBound : ∀ fixed, ReadsAtMost (decode fixed) depth (suffix fixed))
    (keys : List (ActiveKey ctx.role blockCap ctx.keyBytes))
    (keysWithin : ∀ fixed, ReadsWithinKeys encode (decode fixed) keys (suffix fixed))
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : ∀ fixed, StandardOn keys
      (AdaptiveProgram.run
        (ActualProgram.compile (activeContext ctx blockCap fixed) cap (program fixed))
        (partialRandomOracleState (Output := VectorOutput Counter) ∅
          (initialFiberRegisters ctx blockCap dummy registers)))) :
    (∑ fixed : FixedTable ctx blockCap,
      adaptiveReadMass encode (decode fixed)
        (SmzaRp05ActualEventRecertification.event (spec fixed)) (suffix fixed)
        (AdaptiveProgram.run
          (ActualProgram.compile (activeContext ctx blockCap fixed) cap (program fixed))
          (partialRandomOracleState (Output := VectorOutput Counter) ∅
            (initialFiberRegisters ctx blockCap dummy registers)))) ≤
      (6 * (cap : ℝ)^2 * commonBound) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  calc
    _ ≤ ∑ fixed : FixedTable ctx blockCap,
        (6 * (cap : ℝ)^2 * commonBound) *
          normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅
            (initialFiberRegisters ctx blockCap dummy registers)) := by
      apply Finset.sum_le_sum
      intro fixed _
      rw [← sameBound fixed]
      exact actual_program_suffix_event_mass_le_homogeneous
        (activeContext ctx blockCap fixed) cap finish queries depth (spec fixed)
        (program fixed) (initialFiberRegisters ctx blockCap dummy registers)
        encode (decode fixed) (suffix fixed) (readBound fixed) keys (keysWithin fixed)
        supportWithin queriesWithin (total fixed)
    _ = (6 * (cap : ℝ)^2 * commonBound) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
      rw [← Finset.mul_sum]
      congr 1
      exact initial_fiber_mass_sum_eq ctx blockCap dummy registers

end
end HegemonCrypto.SmallWood.SmzaRp05ActualEventFiberMass
