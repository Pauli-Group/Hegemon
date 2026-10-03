import SmzaRp05ConditionedEventJoin

/-! # Homogeneous execution probability, without branch normalization loss

The concrete opcode interpreter is complex-linear in its input amplitudes.
Its absolute normalized bound therefore scales by the actual incoming
squared norm, including zero-mass fibers. The aggregate theorem sums those
weights, not one copy of the loss for every fixed table.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05HomogeneousExecution

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleDatabaseBridge
open SmzaRp05AdaptiveFilteredCollision SmzaRp05AdaptiveKernelInstantiation
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp04CompleteRawRoleCells SmzaChallengeStageTargets
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false

section ScalarFacts
variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

omit [DecidableEq Output] [AddCommGroup Output] [DecidableEq Phase]
    [DecidableEq Workspace] in
theorem norm_squared_smul (scalar : ℂ) (state : State Input Output Phase Workspace) :
    normSquared (scalar • state) = Complex.normSq scalar * normSquared state := by
  simp only [normSquared, Pi.smul_apply, smul_eq_mul, map_mul, Finset.mul_sum]

theorem decompress_at_smul (key : Input) (scalar : ℂ)
    (state : State Input Output Phase Workspace) :
    decompressAt key (scalar • state) = scalar • decompressAt key state := by
  funext basis
  simp only [decompress_at_eq_sum_kernel, Pi.smul_apply, smul_eq_mul,
    mul_assoc, Finset.mul_sum]

omit [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] [Fintype Workspace] [DecidableEq Workspace] in
theorem adaptive_project_smul (event : AdaptiveEvent Input Output Workspace)
    (cap : Nat) (scalar : ℂ) (state : State Input Output Phase Workspace) :
    adaptiveProject event cap (scalar • state) = scalar • adaptiveProject event cap state := by
  funext basis
  simp only [adaptiveProject, Pi.smul_apply, smul_eq_mul]
  split <;> simp

omit [DecidableEq Input] [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] [Fintype Workspace] [DecidableEq Workspace] in
theorem project_smul (property : Database Input Output → Prop)
    (cap : Nat) (scalar : ℂ) (state : State Input Output Phase Workspace) :
    project property cap (scalar • state) = scalar • project property cap state := by
  funext basis
  simp only [project, Pi.smul_apply, smul_eq_mul]
  split <;> simp

omit [Fintype Input] [DecidableEq Input] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase] [Fintype Workspace] [DecidableEq Workspace] in
theorem partial_random_oracle_state_smul (keys : Finset Input) (scalar : ℂ)
    (registers : RegisterBasis (Input := Input) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    partialRandomOracleState (Output := Output) keys (scalar • registers) =
      scalar • partialRandomOracleState keys registers := by
  funext basis
  simp only [partialRandomOracleState, Pi.smul_apply, smul_eq_mul]
  split <;> simp [mul_left_comm]

theorem norm_squared_zero_implies_state_zero (state : State Input Output Phase Workspace)
    (zero : normSquared state = 0) : state = 0 := by
  have normZero : stateNorm state = 0 := by
    have square := state_norm_sq_eq_norm_squared state
    nlinarith [state_norm_nonnegative state]
  have vectorZero : euclideanState state = 0 := norm_eq_zero.mp normZero
  funext basis
  exact congrArg (fun value : EuclideanSpace ℂ (Basis Input Output Phase Workspace) =>
    value basis) vectorZero

end ScalarFacts

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem opcode_apply_smul
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {before after queries : Nat} (opcode : Opcode ctx cap before after queries)
    (scalar : ℂ) (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    (Opcode.compile ctx cap opcode).apply (scalar • state) =
      scalar • (Opcode.compile ctx cap opcode).apply state := by
  cases opcode with
  | query room =>
      change cappedQueryState vectorPhaseSystem cap (scalar • state) =
        scalar • cappedQueryState vectorPhaseSystem cap state
      have projected : strictProject cap (scalar • state) = scalar • strictProject cap state := by
        funext basis
        simp only [strictProject, project, Pi.smul_apply, smul_eq_mul]
        split <;> simp
      have querySmul : queryState vectorPhaseSystem cap
          (scalar • strictProject cap state) =
          scalar • queryState vectorPhaseSystem cap (strictProject cap state) := by
        funext basis
        change queryState vectorPhaseSystem cap
            (fun index => scalar * strictProject cap state index) basis =
          scalar * queryState vectorPhaseSystem cap (strictProject cap state) basis
        exact congrFun (query_state_smul vectorPhaseSystem cap scalar
          (strictProject cap state)) basis
      unfold cappedQueryState
      rw [projected, querySmul]
      funext basis
      simp only [project, Pi.smul_apply, smul_eq_mul]
      split <;> simp
  | privateKernel within transition localStep contractive bounded =>
      change kernelApply transition (scalar • state) =
        scalar • kernelApply transition state
      funext basis
      simp [kernelApply, Pi.smul_apply, smul_eq_mul, mul_assoc, Finset.mul_sum]
  | mark within transition localStep contractive bounded =>
      change kernelApply transition (scalar • state) =
        scalar • kernelApply transition state
      funext basis
      simp [kernelApply, Pi.smul_apply, smul_eq_mul, mul_assoc, Finset.mul_sum]
  | markedWrite after beforeWithin afterWithin transition localStep contractive bounded =>
      change kernelApply transition (scalar • state) =
        scalar • kernelApply transition state
      funext basis
      simp [kernelApply, Pi.smul_apply, smul_eq_mul, mul_assoc, Finset.mul_sum]
  | copy within update authorization =>
      change databaseControlledWorkspaceUpdate update (scalar • state) =
        scalar • databaseControlledWorkspaceUpdate update state
      funext basis
      rfl
  | retainedWrite room key statement marked parsed fresh =>
      have coordinate (old : VectorOutput Counter) (input : State Key (VectorOutput Counter)
          (VectorOutput Counter) BaseWork) :
          coordinateEventProjection key old (scalar • input) =
            scalar • coordinateEventProjection key old input := by
        funext basis
        simp only [coordinateEventProjection, Pi.smul_apply, smul_eq_mul]
        split <;> simp
      have replace (old : VectorOutput Counter) (input : State Key (VectorOutput Counter)
          (VectorOutput Counter) BaseWork) :
          localReplaceReadBranch key old fresh (scalar • input) =
            scalar • localReplaceReadBranch key old fresh input := by
        funext basis
        simp only [localReplaceReadBranch, Pi.smul_apply, smul_eq_mul]
        split <;> simp
      change retainedOldReplace key fresh (scalar • state) =
        scalar • retainedOldReplace key fresh state
      funext basis
      cases slot : basis.workspace.1 with
      | none => simp [retainedOldReplace, slot]
      | some old =>
          have sliced : retainedNoneSlice (scalar • state) = scalar • retainedNoneSlice state := rfl
          simp only [retainedOldReplace, slot, sliced, compressedRetainedBranch,
            decompress_at_smul, coordinate, replace, Pi.smul_apply]

theorem actual_run_smul
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap : Nat) {start finish queries : Nat} (program : ActualProgram ctx cap start finish queries)
    (scalar : ℂ) (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    AdaptiveProgram.run (ActualProgram.compile ctx cap program) (scalar • state) =
      scalar • AdaptiveProgram.run (ActualProgram.compile ctx cap program) state := by
  induction program generalizing state with
  | nil budget => rfl
  | cons first remaining induction =>
      simp only [ActualProgram.compile, AdaptiveProgram.run, opcode_apply_smul, induction]

/-- The complete actual opcode program carries its incoming branch weight.
No subnormalized or positive-mass premise is required. -/
theorem actual_program_bad_mass_le_homogeneous
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (cap finish queries : Nat) (program : ActualProgram ctx cap 0 finish queries)
    (_queriesLe : queries ≤ cap)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    normSquared (adaptiveProject (event ctx) cap
      (AdaptiveProgram.run (ActualProgram.compile ctx cap program)
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) ≤
      (6 * (queries : ℝ)^2 * localBound ctx cap) *
      normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  let initial := partialRandomOracleState (Output := VectorOutput Counter) ∅ registers
  let final := adaptiveProject (event ctx) cap
    (AdaptiveProgram.run (ActualProgram.compile ctx cap program) initial)
  let mass := normSquared initial
  have nonnegative : 0 ≤ mass := by
    unfold mass normSquared
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)
  by_cases emptyMass : mass = 0
  · have initialZero : initial = 0 := norm_squared_zero_implies_state_zero initial emptyMass
    have runZero : AdaptiveProgram.run (ActualProgram.compile ctx cap program) 0 = 0 := by
      simpa using actual_run_smul ctx cap program 0 initial
    have finalZero : final = 0 := by
      funext basis
      simp [final, initialZero, runZero, adaptiveProject]
    change normSquared final ≤ _ * mass
    simp [finalZero, emptyMass, normSquared]
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
    have bound := AdaptiveProgram.counted_query_probability_bound
      (ActualProgram.compile ctx cap program)
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ (scale • registers))
      (partial_random_oracle_empty_bounded (scale • registers)) normalized
      (local_bound_nonnegative ctx cap)
      (initialized_projection_zero ctx cap (scale • registers))
      (ActualProgram.compile_total_leak ctx cap program)
    rw [partial_random_oracle_state_smul, actual_run_smul, adaptive_project_smul,
      norm_squared_smul] at bound
    have weighted := mul_le_mul_of_nonneg_right bound nonnegative
    change normSquared final ≤ _ * mass
    calc
      normSquared final = (Complex.normSq scale * normSquared final) * mass := by
        rw [mul_right_comm, scaleMass, one_mul]
      _ ≤ _ := weighted

end
end HegemonCrypto.SmallWood.SmzaRp05HomogeneousExecution
