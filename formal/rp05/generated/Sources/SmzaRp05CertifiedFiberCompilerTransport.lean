import SmzaRp05CertifiedFiberCompiler

namespace HegemonCrypto.SmallWood.SmzaRp05CertifiedFiberCompiler

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence HegemonCrypto.CanonicalBytes
open SmzaRp05AdaptiveFilteredCollision
open HegemonCrypto.CmsOracleDatabaseBridge
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

theorem reindex_uncapped_query
    {Input Output Phase Left Right : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Left] [DecidableEq Left] [Fintype Right] [DecidableEq Right]
    (system : PhaseSystem Output Phase) (equivalence : Left ≃ Right)
    (state : State Input Output Phase Left) :
    reindexWorkspaceState equivalence (uncappedQuery system state) =
      uncappedQuery system (reindexWorkspaceState equivalence state) := by
  rfl

theorem capped_eq_uncapped
    {Input Output Phase Workspace : Type*}
    [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (system : PhaseSystem Output Phase) (cap occupied : Nat)
    (state : State Input Output Phase Workspace)
    (room : occupied < cap) (bounded : BoundedState occupied state) :
    cappedQueryState system cap state = uncappedQuery system state := by
  rw [capped_query_state_eq_query_state_of_bounded_lt system cap occupied state room bounded,
    query_state_eq_controlled_decompression_phase system cap state
      (bounded_state_strict_support bounded room)]
  rfl

theorem routed_physical_query
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (cap occupied : Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (room : occupied < cap) (bounded : BoundedState occupied state)
    (fiberBounded : BoundedState occupied
      (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state))) :
    routedPhysicalFiber ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap (cappedQueryState vectorPhaseSystem cap state)) =
    (routedPrivateContraction ctx blockCap dummy
      (fixedOtherPhaseContraction vectorPhaseSystem ctx.role blockCap ctx.keyBytes fixed)).apply
      (cappedQueryState vectorPhaseSystem cap
        (routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap state))) := by
  rw [capped_eq_uncapped vectorPhaseSystem cap occupied state room bounded,
    capped_eq_uncapped vectorPhaseSystem cap occupied _ room fiberBounded]
  unfold routedPhysicalFiber
  rw [physical_query_other_role_fiber_to_active]
  unfold fixedActiveUncappedQuery routedPrivateContraction
  rw [reindex_contraction_apply, reindex_uncapped_query]

theorem routed_physical_x_copy
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap) (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys, parseStageQuery (ctx.keyBytes key) = none)
    (update : (XKey keys → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) ≃
        SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    routedPhysicalFiber ctx blockCap dummy fixed (xControlledWorkspaceUpdate keys update state) =
      databaseControlledWorkspaceUpdate
        (fun active => routedWorkUpdate
          (update (activeXView ctx blockCap keys unrecognized active)))
        (routedPhysicalFiber ctx blockCap dummy fixed state) := by
  unfold routedPhysicalFiber
  rw [fixed_fiber_x_copy ctx blockCap dummy fixed keys unrecognized update]
  rfl

/-- The retained slot stays outside the routed base memory. Thus retaining
the old answer commutes with sparse restriction, without an extra oracle
query or a discarded branch. -/
theorem routed_physical_retained_write
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (key : ActiveKey ctx.role blockCap ctx.keyBytes) (fresh : VectorOutput Counter)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    routedPhysicalFiber ctx blockCap dummy fixed (retainedOldReplace key.val fresh state) =
      retainedOldReplace key fresh (routedPhysicalFiber ctx blockCap dummy fixed state) := by
  funext target
  rcases target with ⟨input, phase, ⟨retained, memory⟩, database⟩
  cases retained with
  | none =>
      simp [routedPhysicalFiber, reindexWorkspaceState, basisWorkspaceEquiv,
        activeMemoryEquiv, fixedFiberToActive, activeRegisterEmbed, databaseSlice,
        basisRegisters, retainedOldReplace]
  | some old =>
      simp only [routedPhysicalFiber, reindexWorkspaceState, basisWorkspaceEquiv,
        activeMemoryEquiv, fixedFiberToActive, activeRegisterEmbed, databaseSlice,
        basisRegisters, retainedOldReplace]
      simp only [compressedRetainedBranch, decompress_at_eq_sum_kernel,
        localReplaceReadBranch, coordinateEventProjection, retainedNoneSlice,
        merge_fixed_active_at_active, ← merge_set_active]
      simp only [reindexWorkspaceState, basisWorkspaceEquiv, fixedFiberToActive,
        activeRegisterEmbed, databaseSlice, basisRegisters,
        OnActiveRoute, activeRouteBasis, activeRouteInput, activeRoutePhase,
        ite_mul]
      split_ifs <;> simp_all
      all_goals
        rename_i live routed
        change RoleActive ctx.role blockCap ctx.keyBytes memory.queryInput at live
        simp_all
        all_goals simp [if_neg (not_and.mpr routed)]

end
end HegemonCrypto.SmallWood.SmzaRp05CertifiedFiberCompiler
