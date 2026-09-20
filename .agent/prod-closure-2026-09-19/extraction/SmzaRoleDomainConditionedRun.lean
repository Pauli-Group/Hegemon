import SmzaRoleDomainConditioning

/-!
# Exact phase-run conditioning on the other RP04 role domains

The table split in `SmzaRoleDomainConditioning` is not merely a probability
factorization.  After fixing its second component, every ordinary full-oracle
phase query factors exactly into:

* a live phase query on the selected role plus the complete live complement;
* a diagonal, database-independent contraction using the fixed other-role
  advice.

The final theorem lifts this one-query identity through the complete ordinary
phase-oracle run.  It is an execution equality.  It assumes neither a
stage-security statement nor a readout-distribution bound.
-/
namespace HegemonCrypto.SmallWood.SmzaRoleDomainConditioning

open scoped BigOperators Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsLocalOperator
open SmzaChallengeStageTargets

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Output Phase Workspace : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-! ## Exact reconstruction of the two table components -/

@[simp]
theorem role_table_merge_active
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (key : ActiveKey selected blockCap keyBytes) :
    (roleTableSplit selected blockCap keyBytes).symm (active, fixed) key.val =
      active key := by
  have recovered := congrArg
    (fun tables :
        (ActiveKey selected blockCap keyBytes → Output) ×
          (FixedOtherKey selected blockCap keyBytes → Output) =>
      tables.1 key)
    ((roleTableSplit (Output := Output) selected blockCap keyBytes).apply_symm_apply
      (active, fixed))
  simpa only [role_table_split_active] using recovered

@[simp]
theorem role_table_merge_fixed
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (key : FixedOtherKey selected blockCap keyBytes) :
    (roleTableSplit selected blockCap keyBytes).symm (active, fixed) key.val =
      fixed key := by
  have recovered := congrArg
    (fun tables :
        (ActiveKey selected blockCap keyBytes → Output) ×
          (FixedOtherKey selected blockCap keyBytes → Output) =>
      tables.2 key)
    ((roleTableSplit (Output := Output) selected blockCap keyBytes).apply_symm_apply
      (active, fixed))
  simpa only [role_table_split_fixed] using recovered

/-! ## One exact conditioned phase query -/

/-- Phase supplied by the selected-role table and the complete live
complement.  On a fixed-other-role input it is the identity. -/
def liveRolePhaseMultiplier
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) : ℂ :=
  if isActive : RoleActive selected blockCap keyBytes basis.1 then
    system.character basis.2.1 (active ⟨basis.1, isActive⟩)
  else
    1

/-- Phase supplied only by the fixed, bounded blocks in the other three role
domains.  It is the identity on the selected role and on every live
complement input. -/
def fixedOtherPhaseMultiplier
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) : ℂ :=
  if isActive : RoleActive selected blockCap keyBytes basis.1 then
    1
  else
    system.character basis.2.1 (fixed ⟨basis.1, isActive⟩)

theorem fixed_other_phase_multiplier_normSq
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) :
    Complex.normSq
        (fixedOtherPhaseMultiplier system selected blockCap keyBytes fixed basis) = 1 := by
  by_cases isActive : RoleActive selected blockCap keyBytes basis.1
  · simp [fixedOtherPhaseMultiplier, isActive]
  · simp [fixedOtherPhaseMultiplier, isActive, addChar_normSq]

/-- The live part of a role-conditioned phase query.  The query register is
unchanged; only active inputs consult the live table. -/
def liveRolePhaseRegisterState
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ :=
  fun basis =>
    liveRolePhaseMultiplier system selected blockCap keyBytes active basis *
      state basis

/-- Register-only action of one fixed-other-role phase. -/
def fixedOtherPhaseRegisterState
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ :=
  fun basis =>
    fixedOtherPhaseMultiplier system selected blockCap keyBytes fixed basis *
      state basis

/-- Diagonal kernel for the fixed-other-role action.  It contains no live
oracle database access. -/
def fixedOtherPhaseKernel
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (source target : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) : ℂ :=
  if source = target then
    fixedOtherPhaseMultiplier system selected blockCap keyBytes fixed source
  else
    0

/-- The fixed-domain phase is a genuine database-independent contraction,
not an oracle query and not an assumed stage simulator. -/
def fixedOtherPhaseContraction
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output) :
    DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace) where
  kernel := fixedOtherPhaseKernel system selected blockCap keyBytes fixed
  contractive := by
    intro state
    apply state_norm_le_of_norm_squared_le
    have action :
        liftRegisterKernel
            (fixedOtherPhaseKernel system selected blockCap keyBytes fixed) state =
          fun target =>
            fixedOtherPhaseMultiplier system selected blockCap keyBytes fixed
                (basisRegisters target) * state target := by
      funext target
      rcases target with ⟨input, phase, workspace, database⟩
      simp [liftRegisterKernel, fixedOtherPhaseKernel, basisRegisters]
      ring
    rw [action]
    unfold normSquared
    apply le_of_eq
    apply Finset.sum_congr rfl
    intro basis _
    rw [Complex.normSq_mul,
      fixed_other_phase_multiplier_normSq]
    simp

theorem fixed_other_phase_contraction_apply_register
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    (fixedOtherPhaseContraction system selected blockCap keyBytes fixed).applyRegister state =
      fixedOtherPhaseRegisterState system selected blockCap keyBytes fixed state := by
  funext target
  rcases target with ⟨input, phase, workspace⟩
  simp [DatabaseIndependentContraction.applyRegister,
    fixedOtherPhaseContraction, fixedOtherPhaseKernel,
    fixedOtherPhaseRegisterState]
  ring

/-- At one query, recombining the active and fixed tables gives exactly the
product of the fixed private phase and the live phase. -/
theorem merged_phase_multiplier_eq_conditioned
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (basis : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace)) :
    system.character basis.2.1
        ((roleTableSplit selected blockCap keyBytes).symm (active, fixed) basis.1) =
      fixedOtherPhaseMultiplier system selected blockCap keyBytes fixed basis *
        liveRolePhaseMultiplier system selected blockCap keyBytes active basis := by
  by_cases isActive : RoleActive selected blockCap keyBytes basis.1
  · have mergedValue :
        (roleTableSplit selected blockCap keyBytes).symm (active, fixed) basis.1 =
          active ⟨basis.1, isActive⟩ :=
      role_table_merge_active selected blockCap keyBytes active fixed
        ⟨basis.1, isActive⟩
    rw [mergedValue]
    simp [fixedOtherPhaseMultiplier, liveRolePhaseMultiplier, isActive]
  · have mergedValue :
        (roleTableSplit selected blockCap keyBytes).symm (active, fixed) basis.1 =
          fixed ⟨basis.1, isActive⟩ :=
      role_table_merge_fixed selected blockCap keyBytes active fixed
        ⟨basis.1, isActive⟩
    rw [mergedValue]
    simp [fixedOtherPhaseMultiplier, liveRolePhaseMultiplier, isActive]

/-- Exact one-query execution identity after fixing the other-role table. -/
theorem phase_register_state_eq_role_conditioned
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output)
    (state : RegisterBasis (Input := Key) (Phase := Phase)
      (Workspace := Workspace) → ℂ) :
    phaseRegisterState system
        ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)) state =
      (fixedOtherPhaseContraction system selected blockCap keyBytes fixed).applyRegister
        (liveRolePhaseRegisterState system selected blockCap keyBytes active state) := by
  rw [fixed_other_phase_contraction_apply_register]
  funext basis
  unfold phaseRegisterState fixedOtherPhaseRegisterState
    liveRolePhaseRegisterState
  rw [merged_phase_multiplier_eq_conditioned]
  ring

/-! ## Exact complete-run identity -/

/-- Ordinary phase execution after one fixed other-role table has been moved
into private diagonal contractions.  The family parameter is indexed only by
the live selected-role-plus-complement table. -/
def roleConditionedOracleFamilyRun
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output) :
    List (DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)) →
    ((ActiveKey selected blockCap keyBytes → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → ℂ) →
    ((ActiveKey selected blockCap keyBytes → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → ℂ)
  | [], family => family
  | step :: remaining, family =>
      roleConditionedOracleFamilyRun system selected blockCap keyBytes fixed remaining
        (fun active =>
          step.applyRegister
            ((fixedOtherPhaseContraction system selected blockCap keyBytes fixed).applyRegister
              (liveRolePhaseRegisterState system selected blockCap keyBytes active
                (family active))))

/-- The original full-table phase run and the role-conditioned run are the
same physical execution branch after fixing the other-role advice. -/
theorem oracle_family_run_eq_role_conditioned
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)))
    (family : (Key → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → ℂ)
    (active : ActiveKey selected blockCap keyBytes → Output)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output) :
    oracleFamilyRun system steps family
        ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)) =
      roleConditionedOracleFamilyRun system selected blockCap keyBytes fixed steps
        (fun live =>
          family ((roleTableSplit selected blockCap keyBytes).symm (live, fixed))) active := by
  induction steps generalizing family with
  | nil =>
      rfl
  | cons step remaining inductionHypothesis =>
      rw [oracleFamilyRun, roleConditionedOracleFamilyRun]
      calc
        oracleFamilyRun system remaining
            (fun table =>
              step.applyRegister (phaseRegisterState system table (family table)))
            ((roleTableSplit selected blockCap keyBytes).symm (active, fixed)) =
          roleConditionedOracleFamilyRun system selected blockCap keyBytes fixed remaining
            (fun live =>
              step.applyRegister
                (phaseRegisterState system
                  ((roleTableSplit selected blockCap keyBytes).symm (live, fixed))
                  (family
                    ((roleTableSplit selected blockCap keyBytes).symm
                      (live, fixed))))) active :=
            inductionHypothesis _
        _ =
          roleConditionedOracleFamilyRun system selected blockCap keyBytes fixed remaining
            (fun live =>
              step.applyRegister
                ((fixedOtherPhaseContraction system selected blockCap keyBytes fixed).applyRegister
                  (liveRolePhaseRegisterState system selected blockCap keyBytes live
                    (family
                      ((roleTableSplit selected blockCap keyBytes).symm
                        (live, fixed)))))) active := by
            apply congrArg
              (fun nextFamily =>
                roleConditionedOracleFamilyRun system selected blockCap keyBytes fixed remaining
                  nextFamily active)
            funext live
            rw [phase_register_state_eq_role_conditioned]

/-- Function-level form convenient for substituting the conditioned run into
the subsequent fixed-advice average. -/
theorem oracle_family_run_eq_role_conditioned_family
    (system : PhaseSystem Output Phase)
    (selected : Role) (blockCap : Role → Nat)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (steps : List (DatabaseIndependentContraction
      (Input := Key) (Output := Output) (Phase := Phase)
      (Workspace := Workspace)))
    (family : (Key → Output) →
      RegisterBasis (Input := Key) (Phase := Phase)
        (Workspace := Workspace) → ℂ)
    (fixed : FixedOtherKey selected blockCap keyBytes → Output) :
    (fun active : ActiveKey selected blockCap keyBytes → Output =>
      oracleFamilyRun system steps family
        ((roleTableSplit selected blockCap keyBytes).symm (active, fixed))) =
      roleConditionedOracleFamilyRun system selected blockCap keyBytes fixed steps
        (fun active =>
          family ((roleTableSplit selected blockCap keyBytes).symm
            (active, fixed))) := by
  funext active
  exact oracle_family_run_eq_role_conditioned
    system selected blockCap keyBytes steps family active fixed

end
end HegemonCrypto.SmallWood.SmzaRoleDomainConditioning
