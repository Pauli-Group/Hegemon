import SmzaRp05RoleReadTotality
import SmzaRp05ConditionedExecution

/-! # Scheduled role totality through the actual physical constructors

Only recognized challenge-role cells are promised total after X-copy.
The proof does not assert global standard totality at copied X cells.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ScheduledRoleExecution

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge HegemonCrypto.CmsQuerySequence
open SmzaChallengeStageTargets SmzaRp05CurrentAdaptiveExecution
open SmzaRp05ConditionedExecution SmzaRp05AdaptiveKernelInstantiation
open SmzaRp05PhysicalTerminalRead SmzaRp05RoleReadTotality
open SmzaRp05ChallengeRecordErasure
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem initial_standard_total
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    StandardTotal (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  intro key
  rw [global_decompress_empty_support]
  intro basis absent
  have notTotal : ¬ RecordsExactly (Finset.univ : Finset Key) basis.database := by
    intro total
    obtain ⟨output, recorded⟩ := (total key).mpr (Finset.mem_univ key)
    rw [absent] at recorded
    contradiction
  simp [partialRandomOracleState, notTotal]

theorem total_at_private_gate
    (key : Key)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : TotalAt key state) : TotalAt key (step.apply state) := by
  intro basis absent
  unfold DatabaseIndependentContraction.apply liftRegisterKernel
  apply Finset.sum_eq_zero
  intro registers _
  have zero := total
    { input := registers.1, phase := registers.2.1,
      workspace := registers.2.2, database := basis.database } absent
  rw [zero]
  simp

theorem standard_at_private_gate
    (key : Key)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : TotalAt key (globalDecompress state)) :
    TotalAt key (globalDecompress (step.apply state)) := by
  rw [step.global_decompress_apply_commutes]
  exact total_at_private_gate key step _ total

theorem total_at_retained_old_replace_other
    (key selected : Key) (different : key ≠ selected) (fresh : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : TotalAt key state) : TotalAt key (retainedOldReplace selected fresh state) := by
  have sliced : TotalAt key (retainedNoneSlice state) := by
    intro basis absent
    exact total { basis with workspace := (none, basis.workspace) } absent
  have decompressed := total_at_decompress_at_of_ne selected key
    (retainedNoneSlice state) different.symm sliced
  intro basis absent
  cases slot : basis.workspace.1 with
  | none => simp [retainedOldReplace, slot]
  | some old =>
      have projected : TotalAt key (coordinateEventProjection selected old
          (decompressAt selected (retainedNoneSlice state))) := by
        intro target missing
        simp [coordinateEventProjection, decompressed target missing]
      have replaced : TotalAt key (localReplaceReadBranch selected old fresh
          (coordinateEventProjection selected old
            (decompressAt selected (retainedNoneSlice state)))) := by
        intro target missing
        have stillMissing : (setDatabaseCoordinate target.database selected (some old)) key = none := by
          rw [set_database_coordinate_other target.database different]
          exact missing
        by_cases installed : target.database selected = some fresh
        · simp only [localReplaceReadBranch, if_pos installed]
          exact projected
            { target with database :=
                setDatabaseCoordinate target.database selected (some old) }
            stillMissing
        · simp [localReplaceReadBranch, installed]
      have finished := total_at_decompress_at_of_ne selected key _ different.symm replaced
      simpa only [retainedOldReplace, slot, compressedRetainedBranch] using finished
        { input := basis.input, phase := basis.phase, workspace := basis.workspace.2,
          database := basis.database } absent

theorem standard_at_retained_old_replace_other
    (key selected : Key) (different : key ≠ selected) (fresh : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : TotalAt key (globalDecompress state)) :
    TotalAt key (globalDecompress (retainedOldReplace selected fresh state)) := by
  rw [standard_at_iff_selected]
  rw [decompress_at_retained_old_replace_commutes_of_ne key selected different]
  exact total_at_retained_old_replace_other key selected different fresh _
    ((standard_at_iff_selected key state).mp total)

theorem physical_zero_program_standard_at_role
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    {cap start finish : Nat} (program : PhysicalZeroProgram ctx cap start finish)
    (key : Key) (query : StageQuery) (parsed : parseStageQuery (ctx.keyBytes key) = some query)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : TotalAt key (globalDecompress state)) :
    TotalAt key (globalDecompress (PhysicalZeroProgram.run ctx program state)) := by
  induction program generalizing state with
  | nil budget => exact total
  | privateGate budget within step authorization remaining induction =>
      exact induction (step.apply state) (standard_at_private_gate key step state total)
  | markGate budget within step authorization remaining induction =>
      exact induction (step.apply state) (standard_at_private_gate key step state total)
  | retainedLeafWrite occupied room selected statement marked leaf fresh remaining induction =>
      have different : key ≠ selected := by
        intro same
        have rejected := global_leaf_statement_parse_stage_query_none
          ctx.leafNamespace (ctx.keyBytes selected) statement leaf
        rw [← same, parsed] at rejected
        contradiction
      exact induction _ (standard_at_retained_old_replace_other key selected different fresh state total)
  | markedLeafWrite occupied room selected statement marked leaf fresh remaining induction =>
      have different : key ≠ selected := by
        intro same
        have rejected := global_leaf_statement_parse_stage_query_none
          ctx.leafNamespace (ctx.keyBytes selected) statement leaf
        rw [← same, parsed] at rejected
        contradiction
      exact induction _ (standard_at_retained_old_replace_other key selected different fresh state total)
  | copyX budget within keys unrecognized update authorization remaining induction =>
      exact induction _ (parsed_role_standard_at_x_copy keys ctx.keyBytes unrecognized
        key query parsed update state total)

theorem physical_query_standard_at
    (key : Key) (cap occupied : Nat) (room : occupied < cap)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState occupied state)
    (total : TotalAt key (globalDecompress state)) :
    TotalAt key (globalDecompress (cappedQueryState vectorPhaseSystem cap state)) := by
  rw [capped_query_state_eq_query_state_of_bounded_lt vectorPhaseSystem cap occupied state room bounded,
    global_decompress_query_state_eq_phase vectorPhaseSystem cap state
      (bounded_state_strict_support bounded room)]
  intro basis absent
  simp [phaseQueryState, total basis absent]

theorem certified_physical_program_standard_at_role
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    {cap start finish queries : Nat} (program : CertifiedPhysicalProgram ctx cap start finish queries)
    (key : Key) (query : StageQuery) (parsed : parseStageQuery (ctx.keyBytes key) = some query)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState start state) (total : TotalAt key (globalDecompress state)) :
    TotalAt key (globalDecompress (CertifiedPhysicalProgram.run ctx program state)) := by
  induction program generalizing state with
  | nil budget => exact total
  | zero block remaining induction =>
      have nextBounded := SmzaRp05AdaptiveFilteredCollision.AdaptiveProgram.run_bounded
        (ActualProgram.compile ctx cap (PhysicalZeroProgram.compilePhysical ctx block)) bounded
      rw [← PhysicalZeroProgram.run_eq_compiled_physical] at nextBounded
      exact induction _ nextBounded
        (physical_zero_program_standard_at_role ctx block key query parsed state total)
  | query occupied room remaining induction =>
      have nextBounded : BoundedState (occupied + 1) (cappedQueryState vectorPhaseSystem cap state) := by
        rw [capped_query_state_eq_query_state_of_bounded_lt vectorPhaseSystem cap occupied state room bounded]
        exact query_state_bounded_succ_of_bounded vectorPhaseSystem cap occupied state room bounded
      exact induction _ nextBounded (physical_query_standard_at key cap occupied room state bounded total)

/-- The scheduled-role totality premise is discharged for the complete
certified physical run, including leaf writes and X-copy. -/
theorem certified_initial_run_standard_on_roles
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    {cap finish queries : Nat} (program : CertifiedPhysicalProgram ctx cap 0 finish queries)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (keys : List Key)
    (recognized : ∀ key ∈ keys, ∃ query, parseStageQuery (ctx.keyBytes key) = some query) :
    StandardOn keys (CertifiedPhysicalProgram.run ctx program
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) := by
  intro key member
  obtain ⟨query, parsed⟩ := recognized key member
  exact certified_physical_program_standard_at_role ctx program key query parsed _
    (partial_random_oracle_empty_bounded registers) (initial_standard_total registers key)

end
end HegemonCrypto.SmallWood.SmzaRp05ScheduledRoleExecution
