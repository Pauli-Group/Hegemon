import SmzaRp05AdaptivePhysicalReadBound
import SmzaRp05HomogeneousFiberSum

/-! # Born-weighted adaptive suffixes in the actual fixed-table fibers

Each fixed table may select a different executable answer-adaptive suffix.
Its incoming amplitude remains the literal initial physical fiber. The
finite sum is charged once against the original incoming mass. No success
probability, independence assumption, or normalized postselected state is
an input to the final theorem.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceMass

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05AdaptivePhysicalReadBound SmzaRp05CurrentAdaptiveExecution
open SmzaRp05AdaptiveFilteredCollision SmzaRp05PhysicalTerminalRead
open SmzaRp05PhysicalReadTelescope SmzaRp05RoleReadTotality
open SmzaRp05HomogeneousExecution SmzaRp05HomogeneousFiberSum
open SmzaRp05ConditionedExecution SmzaRp05VectorReadCharge
open SmzaRp05SequentialReadCharge SmzaRoleDomainConditioning
open SmzaChallengeStageTargets SmzaRp04RawMcaSampling
open V8Smz9CoherentVectorMerkle
open SmzaRp05ExecutableMerkleVerifier (Program)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem global_decompress_smul (scalar : ℂ)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    globalDecompress (scalar • state) = scalar • globalDecompress state := by
  unfold globalDecompress
  generalize (Finset.univ : Finset Key).toList = keys
  induction keys generalizing state with
  | nil => rfl
  | cons key rest ih =>
      simp only [decompress_list_cons, ih, decompress_at_smul]

theorem adaptive_read_mass_smul
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → Answer (Counter := Counter) →
      V8SmzaOracleParser.RawDigest)
    (selectedEvent : SmzaRp05CurrentAdaptiveExecution.Work
      (Counter := Counter) (BaseWork := BaseWork) →
      HegemonCrypto.FiniteOracleDatabase.Database Key (Answer (Counter := Counter)) → Prop)
    (program : Program Result) (scalar : ℂ)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    adaptiveReadMass encode decode selectedEvent program (scalar • state) =
      Complex.normSq scalar * adaptiveReadMass encode decode selectedEvent program state := by
  induction program generalizing state with
  | done result =>
      simp only [adaptiveReadMass]
      have projected : workspaceEventProjection selectedEvent (scalar • state) =
          scalar • workspaceEventProjection selectedEvent state := by
        funext basis
        simp only [workspaceEventProjection, Pi.smul_apply, smul_eq_mul]
        split <;> simp
      rw [projected, norm_squared_smul]
  | read raw next ih =>
      simp only [adaptiveReadMass]
      rw [Finset.mul_sum]
      apply Finset.sum_congr rfl
      intro answer _
      have branchLinear : physicalReadBranch (encode raw) answer (scalar • state) =
          scalar • physicalReadBranch (encode raw) answer state := by
        unfold physicalReadBranch
        rw [global_decompress_smul]
        have projected : coordinateEventProjection (encode raw) answer
            (scalar • globalDecompress state) =
            scalar • coordinateEventProjection (encode raw) answer
              (globalDecompress state) := by
          funext basis
          simp only [coordinateEventProjection, Pi.smul_apply, smul_eq_mul]
          split <;> simp
        rw [projected, global_decompress_smul]
      rw [branchLinear, ih]

/-- The adaptive tree bound for an actual opcode program, before taking any
fixed-table sum. All reads are charged to the same query cap. -/
theorem actual_adaptive_read_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap finish queries depth : Nat)
    (program : ActualProgram ctx cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (subnormalized : Subnormalized
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → Answer (Counter := Counter) →
      V8SmzaOracleParser.RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    adaptiveReadMass encode decode (event ctx) suffix
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      6 * (cap : ℝ)^2 * localBound ctx cap := by
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  let compiled := ActualProgram.compile ctx cap program
  let state := AdaptiveProgram.run compiled initial
  let charge := Real.sqrt (6 * localBound ctx cap)
  have bounded : BoundedState finish state := AdaptiveProgram.run_bounded compiled
    (partial_random_oracle_empty_bounded registers)
  have pre := AdaptiveProgram.amplitude_telescope compiled initial
    (partial_random_oracle_empty_bounded registers) subnormalized
  rw [initialized_projection_zero ctx cap registers, state_norm_zero, zero_add,
    ActualProgram.compile_total_leak] at pre
  rw [← workspace_event_eq_adaptive_project_of_bounded (event ctx) cap state
    (bounded_state_mono (by omega) bounded)] at pre
  have amplitude := adaptive_read_role_amplitude_le depth encode decode suffix readBound
    keys keysWithin finish cap state bounded total supportWithin (event ctx)
    (localBound ctx cap) (local_bound_nonnegative ctx cap) (event_instability ctx cap)
  have sourceNorm : stateNorm state ≤ 1 := by
    have mass := AdaptiveProgram.run_subnormalized compiled subnormalized
    simpa using state_norm_le_sqrt state (by norm_num : (0 : ℝ) ≤ 1) mass
  have chargeNonnegative : 0 ≤ charge := Real.sqrt_nonneg _
  have readCharge : (depth : ℝ) * charge * stateNorm state ≤ (depth : ℝ) * charge := by
    nlinarith [mul_le_mul_of_nonneg_left sourceNorm
      (mul_nonneg (Nat.cast_nonneg depth) chargeNonnegative)]
  have count : (queries : ℝ) + depth ≤ cap := by exact_mod_cast queriesWithin
  have totalAmplitude : Real.sqrt (adaptiveReadMass encode decode (event ctx) suffix state) ≤
      (cap : ℝ) * charge := by
    change _ ≤ _ + (depth : ℝ) * charge * stateNorm state at amplitude
    change stateNorm (workspaceEventProjection (event ctx) state) ≤ (queries : ℝ) * charge at pre
    nlinarith [mul_le_mul_of_nonneg_right count chargeNonnegative]
  have squared := (sq_le_sq₀ (Real.sqrt_nonneg _) (by positivity)).2 totalAmplitude
  rw [Real.sq_sqrt (adaptive_read_mass_nonnegative encode decode (event ctx) suffix state),
    mul_pow, show charge^2 = 6 * localBound ctx cap from
      Real.sq_sqrt (mul_nonneg (by norm_num) (local_bound_nonnegative ctx cap))] at squared
  nlinarith

/-- The entire adaptive suffix scales by its actual incoming Born weight,
also for zero-mass fibers. No branch is normalized in the statement. -/
theorem actual_adaptive_read_mass_le_homogeneous
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap finish queries depth : Nat)
    (program : ActualProgram ctx cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : V8SmzaOracleParser.RawInput → Key)
    (decode : V8SmzaOracleParser.RawInput → Answer (Counter := Counter) →
      V8SmzaOracleParser.RawDigest)
    (suffix : Program Result) (readBound : ReadsAtMost decode depth suffix)
    (keys : List Key) (keysWithin : ReadsWithinKeys encode decode keys suffix)
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : StandardOn keys (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) :
    adaptiveReadMass encode decode (event ctx) suffix
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) ≤
      (6 * (cap : ℝ)^2 * localBound ctx cap) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  let mass := normSquared initial
  have nonnegative : 0 ≤ mass := by
    unfold mass normSquared
    exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _
  by_cases emptyMass : mass = 0
  · have initialZero : initial = 0 := norm_squared_zero_implies_state_zero initial emptyMass
    have runZero : AdaptiveProgram.run (ActualProgram.compile ctx cap program) 0 = 0 := by
      simpa using actual_run_smul ctx cap program 0 initial
    have suffixZero : adaptiveReadMass encode decode (event ctx) suffix
        (0 : SmzaRp05CurrentAdaptiveExecution.CmsState
          (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) = 0 := by
      simpa using adaptive_read_mass_smul encode decode (event ctx) suffix 0 initial
    change _ ≤ _ * mass
    change adaptiveReadMass encode decode (event ctx) suffix
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program) initial) ≤ _
    rw [initialZero, runZero, suffixZero, emptyMass, mul_zero]
  · have positive : 0 < mass := lt_of_le_of_ne nonnegative (Ne.symm emptyMass)
    let scale : ℂ := ((Real.sqrt mass)⁻¹ : ℝ)
    have scaleMass : Complex.normSq scale * mass = 1 := by
      have square := Real.sq_sqrt nonnegative
      have nonzero : Real.sqrt mass ≠ 0 := ne_of_gt (Real.sqrt_pos.mpr positive)
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
    have bound := actual_adaptive_read_mass_le ctx cap finish queries depth program
      (scale • registers) normalized encode decode suffix readBound keys keysWithin
      supportWithin queriesWithin scaledTotal
    rw [partial_random_oracle_state_smul, actual_run_smul, adaptive_read_mass_smul] at bound
    have weighted := mul_le_mul_of_nonneg_right bound nonnegative
    change _ ≤ _ * mass
    calc
      _ = (Complex.normSq scale * adaptiveReadMass encode decode (event ctx) suffix
          (AdaptiveProgram.run (ActualProgram.compile ctx cap program) initial)) * mass := by
        rw [mul_right_comm, scaleMass, one_mul]
      _ ≤ _ := weighted

/-- Every advice fiber may choose its own active-domain adaptive suffix.
The unchanged total query/read cap and the actual source fiber weights give
one role loss, rather than one copy per table or per answer branch. -/
theorem sum_fixed_adaptive_suffix_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (cap finish queries depth : Nat)
    (program : ∀ fixed : FixedTable ctx blockCap,
      ActualProgram (activeContext ctx blockCap fixed) cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : V8SmzaOracleParser.RawInput → ActiveKey ctx.role blockCap ctx.keyBytes)
    (decode : FixedTable ctx blockCap → V8SmzaOracleParser.RawInput →
      Answer (Counter := Counter) → V8SmzaOracleParser.RawDigest)
    (suffix : FixedTable ctx blockCap → Program Result)
    (readBound : ∀ fixed, ReadsAtMost (decode fixed) depth (suffix fixed))
    (keys : List (ActiveKey ctx.role blockCap ctx.keyBytes))
    (keysWithin : ∀ fixed, ReadsWithinKeys encode (decode fixed) keys (suffix fixed))
    (supportWithin : finish + depth ≤ cap) (queriesWithin : queries + depth ≤ cap)
    (total : ∀ fixed, StandardOn keys
      (AdaptiveProgram.run (ActualProgram.compile (activeContext ctx blockCap fixed) cap
        (program fixed)) (partialRandomOracleState (Output := VectorOutput Counter) ∅
          (initialFiberRegisters ctx blockCap dummy registers)))) :
    (∑ fixed : FixedTable ctx blockCap,
      adaptiveReadMass encode (decode fixed) (event (activeContext ctx blockCap fixed))
        (suffix fixed)
        (AdaptiveProgram.run (ActualProgram.compile (activeContext ctx blockCap fixed) cap
          (program fixed)) (partialRandomOracleState (Output := VectorOutput Counter) ∅
            (initialFiberRegisters ctx blockCap dummy registers)))) ≤
      (6 * (cap : ℝ)^2 * localBound ctx cap) *
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  calc
    _ ≤ ∑ _fixed : FixedTable ctx blockCap,
        (6 * (cap : ℝ)^2 * localBound ctx cap) *
          normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅
            (initialFiberRegisters ctx blockCap dummy registers)) := by
      apply Finset.sum_le_sum
      intro fixed _
      exact actual_adaptive_read_mass_le_homogeneous (activeContext ctx blockCap fixed)
        cap finish queries depth (program fixed) (initialFiberRegisters ctx blockCap dummy registers)
        encode (decode fixed) (suffix fixed) (readBound fixed) keys (keysWithin fixed)
        supportWithin queriesWithin (total fixed)
    _ = _ := by
      rw [← Finset.mul_sum, initial_fiber_mass_sum_eq]

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveRetainedAdviceMass
