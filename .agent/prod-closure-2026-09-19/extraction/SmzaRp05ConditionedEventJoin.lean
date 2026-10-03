import SmzaRp05ActiveFiberQuery

/-! # Dependent physical event equals the native conditioned event

This is an equality on one reached state, not a substitution of oracle-
dependent advice into a theorem about an independently fixed context.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ConditionedEventJoin

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05DependentAdviceEvent SmzaRp05ActiveFiberEvent
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

def routedPhysicalFiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :=
  reindexWorkspaceState (activeMemoryEquiv ctx)
    (fixedFiberToActive ctx blockCap dummy fixed state)

theorem fixed_advice_event_reindex
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (state : ActiveState ctx blockCap) :
    reindexWorkspaceState (activeMemoryEquiv ctx)
      (workspaceEventProjection
        (activeFiberEvent ctx blockCap fixed (event (contextAtFixed ctx blockCap fixed))) state) =
      workspaceEventProjection (event (activeContext ctx blockCap fixed))
      (reindexWorkspaceState (activeMemoryEquiv ctx) state) := by
  funext basis
  have eventEq : activeFiberEvent ctx blockCap fixed
      (event (contextAtFixed ctx blockCap fixed)) =
      fun memory database => event (activeContext ctx blockCap fixed)
        (activeMemoryEquiv ctx memory) database := by
    funext memory database
    exact congrFun (active_fiber_current_role_event_eq_native
      (contextAtFixed ctx blockCap fixed) blockCap fixed memory) database
  unfold reindexWorkspaceState workspaceEventProjection
  change (if activeFiberEvent ctx blockCap fixed
      (event (contextAtFixed ctx blockCap fixed))
      ((activeMemoryEquiv ctx).symm basis.workspace) basis.database then _ else 0) = _
  rw [eventEq]
  rfl

/-- Exact dependent-event transport through both fixed-table disintegration
and the active-register isometry. All terms refer to the same input state.
The right event is precisely the existing `activeContext` event consumed by
the sparse adaptive-query telescope. -/
theorem dependent_current_role_mass_eq_native_active_masses
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (workspaceEventProjection (dependentCurrentRoleEvent ctx blockCap) state) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection (event (activeContext ctx blockCap fixed))
          (routedPhysicalFiber ctx blockCap dummy fixed state)) := by
  unfold dependentCurrentRoleEvent
  rw [dependent_event_mass_eq_sum_active_event_masses ctx blockCap dummy]
  apply Finset.sum_congr rfl
  intro fixed _
  rw [← reindex_workspace_state_norm_squared (activeMemoryEquiv ctx),
    fixed_advice_event_reindex]
  rfl

theorem reached_dependent_current_role_mass_eq_native_active_masses
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (workspaceEventProjection (dependentCurrentRoleEvent ctx blockCap)
      (otherRoleTransform ctx blockCap state)) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection (event (activeContext ctx blockCap fixed))
          (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state))) :=
  dependent_current_role_mass_eq_native_active_masses ctx blockCap dummy _

end
end HegemonCrypto.SmallWood.SmzaRp05ConditionedEventJoin
