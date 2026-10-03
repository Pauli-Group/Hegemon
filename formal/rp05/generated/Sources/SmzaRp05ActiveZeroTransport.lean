import SmzaRp05HomogeneousFiberSum

/-! # Literal zero-charge transport to the sparse active execution -/
namespace HegemonCrypto.SmallWood.SmzaRp05ActiveZeroTransport

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05ConditionedEventJoin SmzaRp05ActiveFiberQuery
open SmzaRp05AdaptiveKernelInstantiation
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem reindex_contraction_apply
    {Input Output Phase Left Right : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Left] [DecidableEq Left] [Fintype Right] [DecidableEq Right]
    (equivalence : Left ≃ Right)
    (step : DatabaseIndependentContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Left))
    (state : State Input Output Phase Left) :
    reindexWorkspaceState equivalence (step.apply state) =
      (reindexWorkspaceContraction equivalence step).apply
        (reindexWorkspaceState equivalence state) := by
  funext target
  unfold reindexWorkspaceState DatabaseIndependentContraction.apply
    liftRegisterKernel reindexWorkspaceContraction
  rw [← (registerWorkspaceEquiv equivalence).symm.sum_comp]
  rfl

/-- This transports an actual database-blind gate, including an actual mark
gate; no equality-of-executions or event bound is part of the input. -/
theorem fixed_fiber_private_gate
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed (step.apply state) =
      (transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy step).apply
        (fixedFiberToActive ctx blockCap dummy fixed state) := by
  funext target
  change activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (databaseSlice (step.apply state) (mergeFixedActive ctx blockCap fixed target.database))
      (basisRegisters target) =
    databaseSlice
      ((transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy step).apply
        (fixedFiberToActive ctx blockCap dummy fixed state)) target.database (basisRegisters target)
  rw [database_slice_contraction_apply, database_slice_contraction_apply]
  change _ = (transportContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy step).applyRegister
    (activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy
      (databaseSlice state (mergeFixedActive ctx blockCap fixed target.database))) (basisRegisters target)
  rw [transport_contraction_applyRegister_embed]

theorem routed_physical_private_gate
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (step : DatabaseIndependentContraction
      (Input := Key) (Output := VectorOutput Counter) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    routedPhysicalFiber ctx blockCap dummy fixed (step.apply state) =
      (routedPrivateContraction ctx blockCap dummy step).apply
        (routedPhysicalFiber ctx blockCap dummy fixed state) := by
  unfold routedPhysicalFiber routedPrivateContraction
  rw [fixed_fiber_private_gate, reindex_contraction_apply]

/-- Update only the original workspace, retaining original query registers
and hence the active-routing condition. -/
def activeMemoryWorkUpdate
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (update : SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) ≃
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork)) :
    ActiveMemory ctx ≃ ActiveMemory ctx where
  toFun memory := ⟨(memory.original.1, memory.original.2.1, update memory.original.2.2)⟩
  invFun memory := ⟨(memory.original.1, memory.original.2.1, update.symm memory.original.2.2)⟩
  left_inv memory := by cases memory; simp
  right_inv memory := by cases memory; simp

theorem merged_x_view_eq_active_x_view
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (active : ActiveDatabase ctx blockCap) :
    xView keys (mergeFixedActive ctx blockCap fixed active) =
      activeXView ctx blockCap keys unrecognized active := by
  funext key
  exact merge_fixed_active_at_active ctx blockCap fixed active
    (xActiveKey ctx blockCap keys unrecognized key)

theorem fixed_fiber_x_copy
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (update : (XKey keys → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) ≃
        SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed (xControlledWorkspaceUpdate keys update state) =
      databaseControlledWorkspaceUpdate
        (fun active => activeMemoryWorkUpdate ctx
          (update (activeXView ctx blockCap keys unrecognized active)))
        (fixedFiberToActive ctx blockCap dummy fixed state) := by
  funext target
  simp only [fixedFiberToActive, activeRegisterEmbed, databaseSlice,
    xControlledWorkspaceUpdate, databaseControlledWorkspaceUpdate,
    activeMemoryWorkUpdate, basisRegisters]
  simp [OnActiveRoute, activeRouteBasis, activeRouteInput, activeRoutePhase,
    merged_x_view_eq_active_x_view ctx blockCap fixed keys unrecognized target.database]

end
end HegemonCrypto.SmallWood.SmzaRp05ActiveZeroTransport
