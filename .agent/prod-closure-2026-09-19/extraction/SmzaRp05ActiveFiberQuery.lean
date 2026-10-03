import SmzaRp05ActiveFiberEvent

/-! # Charged query of the same sparse physical fiber

This connects the literal two-branch conditioned physical query (live CMS
query versus fixed-table ordinary phase) to the sparse active-key query.
The existing `fixedFiberUncappedQuery` definition alone does not establish
that connection: it is defined by pulling the active query back.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ActiveFiberQuery

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- Exact active query at the routed original registers. A fixed-role
query is routed with zero phase and hence does not consult the live oracle. -/
theorem active_query_at_original_route
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (active : ActiveDatabase ctx blockCap)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork))) :
    databaseSlice
      (uncappedQuery vectorPhaseSystem (fixedFiberToActive ctx blockCap dummy fixed state))
      active (activeRouteBasis vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy registers) =
    if RoleActive ctx.role blockCap ctx.keyBytes registers.1 then
      databaseSlice (uncappedQuery vectorPhaseSystem state)
        (mergeFixedActive ctx blockCap fixed active) registers
    else databaseSlice state (mergeFixedActive ctx blockCap fixed active) registers := by
  rcases registers with ⟨key, phase, workspace⟩
  by_cases live : RoleActive ctx.role blockCap ctx.keyBytes key
  · simp only [live, if_true]
    have atKey : mergeFixedActive ctx blockCap fixed active key = active ⟨key, live⟩ :=
      merge_fixed_active_at_active ctx blockCap fixed active ⟨key, live⟩
    unfold databaseSlice activeRouteBasis activeRouteInput activeRoutePhase
    simp only [dif_pos live, if_pos live]
    simp only [uncappedQuery, controlledDecompress, decompress_at_eq_sum_kernel,
      phaseQueryState]
    simp [fixedFiberToActive, databaseSlice, activeRegisterEmbed, basisRegisters,
      OnActiveRoute, activeRouteBasis, activeRouteInput, activeRoutePhase, live,
      merge_set_active, atKey, recordedPhase]
  · simp only [live, if_false]
    unfold databaseSlice
    rw [uncapped_query_zero_phase_apply vectorPhaseSystem _ _
      (by simp [activeRouteBasis, activeRoutePhase, live])]
    exact active_register_embed_at_route vectorPhaseSystem ctx.role blockCap
      ctx.keyBytes dummy _ _

/-- Lifted private-register action is its register action on each database
slice; this is definitional and does not require total database support. -/
theorem database_slice_contraction_apply
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state : State Input Output Phase Workspace) (database : Database Input Output) :
    databaseSlice (step.apply state) database =
      step.applyRegister (databaseSlice state database) := by
  rfl

/-- Unlike `fixed_fiber_query_restrict`, the left hand side here is the
literal physical conditioned query, not a query defined using the desired
active-state conjugation. -/
theorem physical_conditioned_query_to_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed
      (CertifiedPhysicalProgram.conditionedQuery ctx blockCap state) =
    fixedActiveUncappedQuery ctx blockCap dummy fixed
      (fixedFiberToActive ctx blockCap dummy fixed state) := by
  funext target
  change _ = databaseSlice
    ((transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes fixed)).apply
      (uncappedQuery vectorPhaseSystem (fixedFiberToActive ctx blockCap dummy fixed state)))
    target.database (basisRegisters target)
  rw [database_slice_contraction_apply]
  change _ = (fun registers => ∑ source,
    databaseSlice
      (uncappedQuery vectorPhaseSystem (fixedFiberToActive ctx blockCap dummy fixed state))
      target.database source *
    transportedKernel vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes fixed)
      source registers) (basisRegisters target)
  rw [transported_kernel_action, fixed_other_phase_contraction_apply_register]
  unfold fixedFiberToActive activeRegisterEmbed
  by_cases routed : OnActiveRoute vectorPhaseSystem ctx.role blockCap
      ctx.keyBytes dummy (basisRegisters target)
  · simp only [routed, if_true, fixedOtherPhaseRegisterState, activeRegisterRestrict]
    change databaseSlice (CertifiedPhysicalProgram.conditionedQuery ctx blockCap state)
        (mergeFixedActive ctx blockCap fixed target.database) target.workspace.original =
      fixedOtherPhaseMultiplier vectorPhaseSystem ctx.role blockCap ctx.keyBytes fixed
          target.workspace.original *
        databaseSlice
          (uncappedQuery vectorPhaseSystem (fixedFiberToActive ctx blockCap dummy fixed state))
          target.database
          (activeRouteBasis vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
            target.workspace.original)
    rw [active_query_at_original_route]
    by_cases live : RoleActive ctx.role blockCap ctx.keyBytes target.workspace.original.1
    · simp [CertifiedPhysicalProgram.conditionedQuery, databaseSlice,
        fixedOtherPhaseMultiplier, live]
    · simp [CertifiedPhysicalProgram.conditionedQuery, databaseSlice,
        fixedOtherPhaseMultiplier, live, phaseQueryState, recordedPhase,
        mergeFixedActive]
  · simp [routed]

/-- The same physical queried state, partially decompressed and restricted
to the same fixed fiber, evolves by the actual sparse query plus its private
fixed phase. No equality-of-executions premise is supplied by a caller. -/
theorem physical_query_other_role_fiber_to_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap (uncappedQuery vectorPhaseSystem state)) =
    fixedActiveUncappedQuery ctx blockCap dummy fixed
      (fixedFiberToActive ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state)) := by
  rw [other_role_transform_uncapped_query]
  exact physical_conditioned_query_to_active ctx blockCap dummy fixed _

end
end HegemonCrypto.SmallWood.SmzaRp05ActiveFiberQuery
