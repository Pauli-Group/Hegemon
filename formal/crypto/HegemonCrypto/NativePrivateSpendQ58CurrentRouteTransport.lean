import HegemonCrypto.NativePrivateSpendQ58CurrentFiberMassTransport
import HegemonCrypto.NativePrivateSpendQ58ActiveEventProjection
import SmzaRp05ConditionedExecution
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRouteTransport
open scoped Classical
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open SmzaChallengeStageTargets (Role)
open V8SmzaOracleParser (RawInput)
open SmzaRoleDomainConditioning (RoleActive)
open SmzaRp05CurrentAdaptiveExecution (Context CmsState)
open SmzaRp05ConditionedExecution (fixedFiberToActive otherRoleTransform)
open NativePrivateSpendQ58ActiveEventProjection
  (ActiveKey FixedTable SparseState restrictFiber onRoute restoreBasis merge_on_fiber)
open NativePrivateSpendQ58PartitionTransport (conditioned projectFiber otherTransform)
namespace F
export NativePrivateSpendQ58CurrentFiberMassTransport
  (routingTag routing_predicate_is_literal_current)
end F
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive)
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end C
noncomputable section
set_option autoImplicit false
variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]
abbrev cap : Role → Nat := fun _ => 1
abbrev W := SmzaRp05CurrentAdaptiveExecution.Work
  (Counter := Counter) (BaseWork := BaseWork)
variable (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))

-- Only role/key partition operators consume this routing context. Actual
-- role events replace this inert metadata with deterministic fixed-table advice.
def routeContext (role : Role) (bytes : Key → RawInput) :=
  { ctx with
    role := role
    keyBytes := F.routingTag role bytes
    advice := fun _ _ _ _ => none }

omit [Fintype Key] [DecidableEq Key] in
theorem route_predicate (role : Role) (bytes : Key → RawInput) :
    RoleActive role cap (F.routingTag role bytes) = C.RoleActive role C.currentRoleCaps bytes := by
  funext key
  exact propext (F.routing_predicate_is_literal_current role bytes key)

private theorem retained_restrict
    (dummy : ActiveKey (RoleActive ctx.role cap ctx.keyBytes))
    (fixed : FixedTable (Counter := Counter) (RoleActive ctx.role cap ctx.keyBytes))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx cap dummy fixed (otherRoleTransform ctx cap state) =
      restrictFiber (RoleActive ctx.role cap ctx.keyBytes) dummy fixed
        (conditioned (RoleActive ctx.role cap ctx.keyBytes) fixed state) := by
  funext basis
  have otherEq : otherRoleTransform ctx cap state =
      otherTransform (RoleActive ctx.role cap ctx.keyBytes) state := by
    have keysEq : SmzaRp05ConditionedExecution.fixedOtherKeys ctx cap =
        NativePrivateSpendQ58PartitionTransport.fixedKeys
          (RoleActive ctx.role cap ctx.keyBytes) := by
      ext key
      simp only [SmzaRp05ConditionedExecution.mem_fixed_other_keys,
        NativePrivateSpendQ58PartitionTransport.mem_fixed_keys,
        SmzaRoleDomainConditioning.FixedOtherRole]
    unfold SmzaRp05ConditionedExecution.otherRoleTransform
      NativePrivateSpendQ58PartitionTransport.otherTransform
    rw [keysEq]
  have routeEq :
      SmzaRoleDomainConditioning.activeRouteBasis
        V8Smz9CoherentVectorMerkle.vectorPhaseSystem ctx.role cap ctx.keyBytes dummy
        (basisRegisters basis).2.2.original =
      NativePrivateSpendQ58ActiveEventProjection.route
        (RoleActive ctx.role cap ctx.keyBytes) dummy (basisRegisters basis).2.2.original := by
    rfl
  have predicateEq :
      SmzaRoleDomainConditioning.OnActiveRoute
        V8Smz9CoherentVectorMerkle.vectorPhaseSystem ctx.role cap ctx.keyBytes dummy
        (basisRegisters basis) =
      onRoute (RoleActive ctx.role cap ctx.keyBytes) dummy (basisRegisters basis) := by
    unfold SmzaRoleDomainConditioning.OnActiveRoute onRoute
    rw [routeEq]
  have mergeEq :
      SmzaRp05ConditionedExecution.mergeFixedActive ctx cap fixed basis.database =
      NativePrivateSpendQ58ActiveEventProjection.merge
        (RoleActive ctx.role cap ctx.keyBytes) fixed basis.database := by
    rfl
  have restoreEq :
      SmzaRoleDomainConditioning.databaseSlice (otherRoleTransform ctx cap state)
        (SmzaRp05ConditionedExecution.mergeFixedActive ctx cap fixed basis.database)
        (basisRegisters basis).2.2.original =
      otherTransform (RoleActive ctx.role cap ctx.keyBytes) state
        (restoreBasis (RoleActive ctx.role cap ctx.keyBytes) fixed basis) := by
    rw [otherEq]
    dsimp only [SmzaRoleDomainConditioning.databaseSlice]
    rw [mergeEq]
    rfl
  dsimp only [fixedFiberToActive, SmzaRoleDomainConditioning.activeRegisterEmbed,
    NativePrivateSpendQ58ActiveEventProjection.restrictFiber]
  rw [predicateEq, restoreEq]
  simp only [conditioned, projectFiber, restoreBasis, merge_on_fiber, if_true]

theorem fiber_exact (role : Role) (bytes : Key → RawInput)
    (dummy : ActiveKey (RoleActive role cap (F.routingTag role bytes)))
    (fixed : FixedTable (Counter := Counter) (RoleActive role cap (F.routingTag role bytes)))
    (state : CmsState (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    let h := route_predicate role bytes
    Eq.mp (congrArg (fun live => SparseState (Counter := Counter) (Work := W) live) h)
      (fixedFiberToActive (routeContext ctx role bytes) cap dummy fixed
        (otherRoleTransform (routeContext ctx role bytes) cap state)) =
    restrictFiber _ (h ▸ dummy) (h ▸ fixed) (conditioned _ (h ▸ fixed) state) := by
  dsimp only
  rw [retained_restrict]
  have transport (live : Key → Prop)
      (h : RoleActive role cap (F.routingTag role bytes) = live) :
      Eq.mp (congrArg (fun p => SparseState (Counter := Counter) (Work := W) p) h)
        (restrictFiber _ dummy fixed (conditioned _ fixed state)) =
      restrictFiber live (h ▸ dummy) (h ▸ fixed) (conditioned live (h ▸ fixed) state) := by
    cases h
    rfl
  exact transport _ (route_predicate role bytes)
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentRouteTransport
