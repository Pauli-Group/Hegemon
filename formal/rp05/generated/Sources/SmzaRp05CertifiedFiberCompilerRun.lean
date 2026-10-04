import SmzaRp05CertifiedFiberCompilerTransport

/-! Literal execution equality for the structural sparse prefix compiler. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CertifiedFiberCompiler

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CanonicalBytes
open SmzaRp05AdaptiveFilteredCollision
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05ConditionedEventJoin SmzaRp05ActiveFiberQuery
open SmzaRp05AdaptiveKernelInstantiation SmzaRp05ActiveZeroTransport
open SmzaRp05HomogeneousFiberSum V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem contraction_bounded
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (budget : Nat) {state : State Input Output Phase Workspace}
    (bounded : BoundedState budget state) : BoundedState budget (step.apply state) := by
  have result := database_independent_transition_bounded step budget bounded
  simpa only [kernel_apply_database_independent_transition] using result

/-- Both support bounds are propagated from the actual opcode actions.
No intermediate execution correspondence is supplied as constructor data. -/
theorem run_eq_compiled_prefix
    {contexts : Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap start finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap start finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role) (blockCap : Role → Nat)
    (dummy : ActiveKey (contexts role).role blockCap (contexts role).keyBytes)
    (fixed : FixedTable (contexts role) blockCap)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState start state)
    (fiberBounded : BoundedState start
      (routedPhysicalFiber (contexts role) blockCap dummy fixed
        (otherRoleTransform (contexts role) blockCap state))) :
    routedPhysicalFiber (contexts role) blockCap dummy fixed
      (otherRoleTransform (contexts role) blockCap (PhysicalProgramSkeleton.run skeleton state)) =
    AdaptiveProgram.run (ActualProgram.compile (activeContext (contexts role) blockCap fixed) cap
      (compilePrefix certified role blockCap dummy fixed))
      (routedPhysicalFiber (contexts role) blockCap dummy fixed
        (otherRoleTransform (contexts role) blockCap state)) := by
  induction certified generalizing state with
  | nil budget => rfl
  | query occupied room remaining ih =>
      have nextBounded := (Opcode.compile (contexts role) cap
        (.query occupied room)).preservesBounded bounded
      have transport := routed_physical_query (contexts role) blockCap dummy fixed
        cap occupied state room bounded fiberBounded
      have nextFiberBounded : BoundedState (occupied + 1)
          (routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap
              (cappedQueryState vectorPhaseSystem cap state))) := by
        rw [transport]
        apply contraction_bounded
        exact (Opcode.compile (activeContext (contexts role) blockCap fixed) cap
          (.query occupied room)).preservesBounded fiberBounded
      have result := ih (cappedQueryState vectorPhaseSystem cap state)
        nextBounded nextFiberBounded
      rw [transport] at result
      simpa [PhysicalProgramSkeleton.run, compilePrefix, consZero, ActualProgram.compile,
        AdaptiveProgram.run, privateOpcode, Opcode.compile,
        certifiedKernelStep, certifiedOrdinaryQueryStep,
        kernel_apply_database_independent_transition] using result
  | privateGate budget within step authorization remaining ih =>
      have transport :
          routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap (step.apply state)) =
          (routedPrivateContraction (contexts role) blockCap dummy step).apply
            (routedPhysicalFiber (contexts role) blockCap dummy fixed
              (otherRoleTransform (contexts role) blockCap state)) := by
        rw [other_role_transform_private_commutes, routed_physical_private_gate]
      have nextFiberBounded : BoundedState budget
          (routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap (step.apply state))) := by
        rw [transport]
        exact contraction_bounded _ _ fiberBounded
      have result := ih (step.apply state) (contraction_bounded step budget bounded) nextFiberBounded
      rw [transport] at result
      simpa [PhysicalProgramSkeleton.run, compilePrefix, consZero, ActualProgram.compile,
        AdaptiveProgram.run, privateOpcode, Opcode.compile, certifiedKernelStep,
        kernel_apply_database_independent_transition] using result
  | markGate budget within step authorization remaining ih =>
      have transport :
          routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap (step.apply state)) =
          (routedPrivateContraction (contexts role) blockCap dummy step).apply
            (routedPhysicalFiber (contexts role) blockCap dummy fixed
              (otherRoleTransform (contexts role) blockCap state)) := by
        rw [other_role_transform_private_commutes, routed_physical_private_gate]
      have nextFiberBounded : BoundedState budget
          (routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap (step.apply state))) := by
        rw [transport]
        exact contraction_bounded _ _ fiberBounded
      have result := ih (step.apply state) (contraction_bounded step budget bounded) nextFiberBounded
      rw [transport] at result
      simpa [PhysicalProgramSkeleton.run, compilePrefix, consZero, ActualProgram.compile,
        AdaptiveProgram.run, markOpcode, Opcode.compile, certifiedKernelStep,
        kernel_apply_database_independent_transition] using result
  | retainedLeafWrite occupied room key statement fresh marked parsed remaining ih =>
      let activeKey : ActiveKey (contexts role).role blockCap (contexts role).keyBytes :=
        ⟨key, canonical_leaf_is_active (contexts role) blockCap key statement (parsed role)⟩
      have transport :
          routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap (retainedOldReplace key fresh state)) =
          retainedOldReplace activeKey fresh
            (routedPhysicalFiber (contexts role) blockCap dummy fixed
              (otherRoleTransform (contexts role) blockCap state)) := by
        rw [other_role_transform_retained_old_replace_leaf
          (contexts role) blockCap key statement (parsed role) fresh]
        exact routed_physical_retained_write (contexts role) blockCap dummy fixed activeKey fresh _
      have nextFiberBounded : BoundedState (occupied + 1)
          (routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap (retainedOldReplace key fresh state))) := by
        rw [transport]
        exact retained_old_replace_bounded_succ activeKey fresh occupied fiberBounded
      have result := ih (retainedOldReplace key fresh state)
        (retained_old_replace_bounded_succ key fresh occupied bounded) nextFiberBounded
      rw [transport] at result
      simpa [PhysicalProgramSkeleton.run, compilePrefix, consZero, ActualProgram.compile,
        AdaptiveProgram.run, Opcode.compile, vectorRetainedOldReplaceStep,
        retainedOldReplaceStep, activeKey] using result
  | copyX budget within keys update unrecognized authorization remaining ih =>
      have transport :
          routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap
              (xControlledWorkspaceUpdate keys update state)) =
          databaseControlledWorkspaceUpdate
            (fun database => routedWorkUpdate
              (update (activeXView (contexts role) blockCap keys (unrecognized role) database)))
            (routedPhysicalFiber (contexts role) blockCap dummy fixed
              (otherRoleTransform (contexts role) blockCap state)) := by
        rw [other_role_transform_x_copy (contexts role) blockCap keys (unrecognized role) update,
          routed_physical_x_copy (contexts role) blockCap dummy fixed keys (unrecognized role) update]
      have nextFiberBounded : BoundedState budget
          (routedPhysicalFiber (contexts role) blockCap dummy fixed
            (otherRoleTransform (contexts role) blockCap
              (xControlledWorkspaceUpdate keys update state))) := by
        rw [transport]
        exact database_controlled_workspace_update_bounded _ budget fiberBounded
      have nextBounded : BoundedState budget (xControlledWorkspaceUpdate keys update state) :=
        database_controlled_workspace_update_bounded _ budget bounded
      have result := ih (xControlledWorkspaceUpdate keys update state) nextBounded nextFiberBounded
      rw [transport] at result
      simpa [PhysicalProgramSkeleton.run, compilePrefix, consZero, ActualProgram.compile,
        AdaptiveProgram.run, Opcode.compile, databaseControlledWorkspaceUpdateStep] using result

/-- The same literal common execution, started at the empty random oracle,
is exactly the native sparse program for each same-oracle fixed table. -/
theorem initial_run_eq_compiled_prefix
    {contexts : Role → Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork)}
    {cap finish queries : Nat}
    {skeleton : PhysicalProgramSkeleton (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) cap 0 finish queries}
    (certified : CertifiedFor contexts skeleton)
    (role : Role) (blockCap : Role → Nat)
    (dummy : ActiveKey (contexts role).role blockCap (contexts role).keyBytes)
    (fixed : FixedTable (contexts role) blockCap)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    routedPhysicalFiber (contexts role) blockCap dummy fixed
      (otherRoleTransform (contexts role) blockCap
        (PhysicalProgramSkeleton.run skeleton
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) =
    AdaptiveProgram.run (ActualProgram.compile (activeContext (contexts role) blockCap fixed) cap
      (compilePrefix certified role blockCap dummy fixed))
      (partialRandomOracleState (Output := VectorOutput Counter) ∅
        (initialFiberRegisters (contexts role) blockCap dummy registers)) := by
  have initialEq := routed_physical_initial_eq_empty_fiber
    (contexts role) blockCap dummy fixed registers
  have fiberBounded : BoundedState 0
      (routedPhysicalFiber (contexts role) blockCap dummy fixed
        (otherRoleTransform (contexts role) blockCap
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))) := by
    rw [initialEq]
    exact partial_random_oracle_empty_bounded _
  simpa only [initialEq] using run_eq_compiled_prefix certified role blockCap dummy fixed _
    (partial_random_oracle_empty_bounded registers) fiberBounded

end
end HegemonCrypto.SmallWood.SmzaRp05CertifiedFiberCompiler
