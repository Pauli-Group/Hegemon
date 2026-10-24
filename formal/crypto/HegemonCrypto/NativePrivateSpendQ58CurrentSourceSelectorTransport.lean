import HegemonCrypto.NativePrivateSpendQ58CurrentRouteTransport
import SmzaRp05OrdinarySoundnessStandardTotal

/-! Current source selectors on retained PR205 operators. Source only. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceSelectorTransport
open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge HegemonCrypto.FiniteOracleDatabase
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches physicalRun)
open SmzaRp05ConditionedExecution (XKey xView)
open SmzaRp05OrdinarySoundnessExecution (OrdinaryPrefix ordinaryRun)
open SmzaChallengeStageTargets (Role)
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping (Key Counter keyBytes encode decode)
end G
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive parseCurrentStageQuery)
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end C
namespace P
export NativePrivateSpendQ58PartitionTransport (FixedTable conditioned)
end P
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge merge_active)
end A
namespace RT
export NativePrivateSpendQ58CurrentRouteTransport (cap routeContext route_predicate)
end RT
namespace T
export SmzaRp05CurrentNonchallengeSelectorTransport
  (nonchallengeSelectorProjection nonchallenge_selector_projection_other_role_transform)
end T
namespace ST
export SmzaRp05OrdinarySoundnessStandardTotal
  (fixed_other_coordinate_total_after_transform nonchallenge_selector_projection_eq_supported
   physical_run_branch_standard_total initialized_ordinary_run_standard_total)
end ST
namespace CE
export SmzaRp05CurrentAdaptiveExecution (Context Work CmsState)
export SmzaRp05ConditionedExecution
  (fixedOtherKeys mem_fixed_other_keys otherRoleTransform
   other_role_transform_norm_squared)
end CE
namespace AE
export SmzaRp05DependentAdviceEvent (dependent_fixed_event_mass_eq_sum_fibers)
end AE
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
variable {Result BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]

/-- All and only CURRENT parser-free keys; never a routing-tag key set. -/
def sourceKeys (root : Program Result) : Finset (G.Key root) :=
  Finset.univ.filter fun key => C.parseCurrentStageQuery (G.keyBytes root key) = none
abbrev SourceView (root : Program Result) := XKey (sourceKeys root) → Option (VectorOutput G.Counter)
abbrev W := CE.Work (Counter := G.Counter) (BaseWork := BaseWork)
abbrev S (root : Program Result) := CE.CmsState
  (Key := G.Key root) (Counter := G.Counter) (BaseWork := BaseWork)
abbrev Context (root : Program Result) := CE.Context
  (Key := G.Key root) (Counter := G.Counter) (BaseWork := BaseWork)
def live (root : Program Result) (role : Role) := C.RoleActive role C.currentRoleCaps (G.keyBytes root)
def sourceProjection (root : Program Result) (select : SourceView root → W (BaseWork := BaseWork) → Prop) :=
  T.nonchallengeSelectorProjection (BaseWork := BaseWork) (sourceKeys root) select

theorem source_keys_active_for_each_role (root : Program Result) (role : Role)
    (key : G.Key root) (member : key ∈ sourceKeys root) : live root role key := by
  have parsed := (Finset.mem_filter.mp member).2
  simp only [live, C.RoleActive, parsed]

def activeSourceView (root : Program Result) (role : Role)
    (database : Database (A.ActiveKey (live root role)) (VectorOutput G.Counter)) : SourceView root :=
  fun key => database ⟨key.val, source_keys_active_for_each_role root role key.val key.property⟩
theorem source_view_fixed_completion (root : Program Result) (role : Role)
    (fixed : P.FixedTable (Counter := G.Counter) (live root role))
    (database : Database (A.ActiveKey (live root role)) (VectorOutput G.Counter)) :
    xView (sourceKeys root) (A.merge (live root role) fixed database) =
      activeSourceView root role database := by
  funext key
  exact A.merge_active (live root role) fixed database
    ⟨key.val, source_keys_active_for_each_role root role key.val key.property⟩

private theorem source_outside_fixed (root : Program Result) (ctx : Context (BaseWork := BaseWork) root)
    (role : Role) (key : G.Key root)
    (fixed : key ∈ CE.fixedOtherKeys (RT.routeContext ctx role (G.keyBytes root)) RT.cap) :
    key ∉ sourceKeys root := by
  intro member
  have inactive := (CE.mem_fixed_other_keys _ _ key).mp fixed
  change ¬SmzaRoleDomainConditioning.RoleActive role RT.cap
    (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes root)) key at inactive
  have active := source_keys_active_for_each_role root role key member
  exact inactive ((RT.route_predicate role (G.keyBytes root)).symm ▸ active)

theorem current_source_selector_commutes (root : Program Result) (ctx : Context (BaseWork := BaseWork) root)
    (role : Role) (select : SourceView root → W (BaseWork := BaseWork) → Prop) (state : S (BaseWork := BaseWork) root) :
    sourceProjection root select
      (CE.otherRoleTransform (RT.routeContext ctx role (G.keyBytes root)) RT.cap state) =
    CE.otherRoleTransform (RT.routeContext ctx role (G.keyBytes root)) RT.cap
      (sourceProjection root select state) := by
  exact T.nonchallenge_selector_projection_other_role_transform _ _ _ select state
    (source_outside_fixed root ctx role)

theorem current_source_selector_mass_eq_sum_conditioned_of_standard_total
    (root : Program Result) (ctx : Context (BaseWork := BaseWork) root) (role : Role)
    (select : SourceView root → W (BaseWork := BaseWork) → Prop) (state : S (BaseWork := BaseWork) root)
    (total : SmzaRp05PhysicalTerminalRead.StandardTotal state) :
    (∑ fixed : P.FixedTable (Counter := G.Counter) (live root role),
      normSquared (sourceProjection root select (P.conditioned (live root role) fixed state))) =
    normSquared (sourceProjection root select state) := by
  let routed := RT.routeContext ctx role (G.keyBytes root)
  have fixedTotal := ST.fixed_other_coordinate_total_after_transform routed RT.cap state total
  have supported := ST.nonchallenge_selector_projection_eq_supported routed RT.cap
    (sourceKeys root) select (CE.otherRoleTransform routed RT.cap state) fixedTotal
  have split := AE.dependent_fixed_event_mass_eq_sum_fibers routed RT.cap
    (fun _ work database => select (xView (sourceKeys root) database) work)
    (CE.otherRoleTransform routed RT.cap state)
  rw [← supported] at split
  have commuting := current_source_selector_commutes root ctx role select state
  have preserved := congrArg normSquared commuting
  rw [CE.other_role_transform_norm_squared] at preserved
  have weighted := split.symm.trans preserved
  have keysEq : CE.fixedOtherKeys routed RT.cap =
      NativePrivateSpendQ58PartitionTransport.fixedKeys
        (SmzaRoleDomainConditioning.RoleActive role RT.cap
          (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes root))) := by
    ext key
    simp only [CE.mem_fixed_other_keys, NativePrivateSpendQ58PartitionTransport.mem_fixed_keys,
      SmzaRoleDomainConditioning.FixedOtherRole]
    rfl
  have otherEq : CE.otherRoleTransform routed RT.cap state =
      NativePrivateSpendQ58PartitionTransport.otherTransform
        (SmzaRoleDomainConditioning.RoleActive role RT.cap
          (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes root))) state := by
    unfold SmzaRp05ConditionedExecution.otherRoleTransform
      NativePrivateSpendQ58PartitionTransport.otherTransform
    rw [keysEq]
  have fiberEq (fixed : SmzaRp05ConditionedExecution.FixedTable routed RT.cap) :
      SmzaRp05ConditionedExecution.fixedFiberProjection routed RT.cap fixed
        (CE.otherRoleTransform routed RT.cap state) =
      P.conditioned
        (SmzaRoleDomainConditioning.RoleActive role RT.cap
          (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes root)))
        fixed state := by
    rw [otherEq]
    funext basis
    unfold SmzaRp05ConditionedExecution.fixedFiberProjection
      NativePrivateSpendQ58PartitionTransport.conditioned
      NativePrivateSpendQ58PartitionTransport.projectFiber
    have predicateEq : SmzaRp05ConditionedExecution.fixedFiber routed RT.cap fixed basis.database =
        NativePrivateSpendQ58PartitionTransport.onFiber
          (SmzaRoleDomainConditioning.RoleActive role RT.cap
            (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes root)))
          fixed basis.database := by
      rfl
    rw [predicateEq]
  have massBridge :
      (∑ fixed : SmzaRp05ConditionedExecution.FixedTable routed RT.cap,
        normSquared (sourceProjection root select
          (SmzaRp05ConditionedExecution.fixedFiberProjection routed RT.cap fixed
            (CE.otherRoleTransform routed RT.cap state)))) =
      (∑ fixed : P.FixedTable (Counter := G.Counter)
        (SmzaRoleDomainConditioning.RoleActive role RT.cap
          (NativePrivateSpendQ58CurrentFiberMassTransport.routingTag role (G.keyBytes root))),
        normSquared (sourceProjection root select (P.conditioned _ fixed state))) := by
    apply Finset.sum_congr
    · exact congrArg
        (fun inst : Fintype (SmzaRp05ConditionedExecution.FixedTable routed RT.cap) =>
          @Finset.univ _ inst) (Subsingleton.elim _ _)
    · intro fixed _
      exact congrArg (fun current : S (BaseWork := BaseWork) root =>
        normSquared (sourceProjection root select current)) (fiberEq fixed)
  have converted := massBridge.symm.trans weighted
  rw [RT.route_predicate role (G.keyBytes root)] at converted
  exact converted

variable (root : Program Result) {cap finish queries : Nat}
    («prefix» : OrdinaryPrefix (Key := G.Key root) (Counter := G.Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := G.Key root) (Phase := VectorOutput G.Counter)
      (Workspace := W (BaseWork := BaseWork)) → ℂ)
def reached (branch : Branches G.decode root) : S (BaseWork := BaseWork) root :=
  physicalRun (G.encode root) G.decode root branch
    (ordinaryRun «prefix» (partialRandomOracleState (Output := VectorOutput G.Counter) ∅ registers))

theorem current_source_selector_mass_eq_sum_conditioned
    (branch : Branches G.decode root) (ctx : Context (BaseWork := BaseWork) root) (role : Role)
    (select : SourceView root → W (BaseWork := BaseWork) → Prop) :
    (∑ fixed : P.FixedTable (Counter := G.Counter) (live root role),
      normSquared (sourceProjection root select
        (P.conditioned (live root role) fixed (reached root «prefix» registers branch)))) =
    normSquared (sourceProjection root select (reached root «prefix» registers branch)) := by
  apply current_source_selector_mass_eq_sum_conditioned_of_standard_total root ctx role select
  exact ST.physical_run_branch_standard_total (G.encode root) G.decode root branch _
    (ST.initialized_ordinary_run_standard_total «prefix» registers)

def unionSelector (select : Role → SourceView root → W (BaseWork := BaseWork) → Prop) : SourceView root → W (BaseWork := BaseWork) → Prop :=
  fun view work => ∃ role, select role view work

omit [DecidableEq BaseWork] in
theorem current_four_source_selector_union_le_sum
    (select : Role → SourceView root → W (BaseWork := BaseWork) → Prop) (state : S (BaseWork := BaseWork) root) :
    normSquared (sourceProjection root (unionSelector root select) state) ≤
      ∑ role : Role, normSquared (sourceProjection root (select role) state) := by
  unfold sourceProjection unionSelector T.nonchallengeSelectorProjection normSquared workspaceEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  by_cases hit : ∃ role, select role (xView (sourceKeys root) basis.database) basis.workspace
  · rw [if_pos hit]
    obtain ⟨role, chosen⟩ := hit
    have one := Finset.single_le_sum
      (fun other _ => Complex.normSq_nonneg
        (if select other (xView (sourceKeys root) basis.database) basis.workspace then state basis else 0))
      (Finset.mem_univ role)
    simpa only [if_pos chosen] using one
  · rw [if_neg hit]
    simpa using Finset.sum_nonneg
      (fun role _ => Complex.normSq_nonneg
        (if select role (xView (sourceKeys root) basis.database) basis.workspace then state basis else 0))

theorem current_four_source_union_le_weighted_conditioned
    (ctx : Context (BaseWork := BaseWork) root) (select : Role → SourceView root → W (BaseWork := BaseWork) → Prop) (state : S (BaseWork := BaseWork) root)
    (total : SmzaRp05PhysicalTerminalRead.StandardTotal state) :
    normSquared (sourceProjection root (unionSelector root select) state) ≤
    (∑ role : Role, ∑ fixed : P.FixedTable (Counter := G.Counter) (live root role),
      normSquared (sourceProjection root (select role) (P.conditioned (live root role) fixed state))) := by
  calc
    _ ≤ ∑ role : Role, normSquared (sourceProjection root (select role) state) :=
      current_four_source_selector_union_le_sum root select state
    _ = _ := by
      apply Finset.sum_congr rfl
      intro role _
      exact (current_source_selector_mass_eq_sum_conditioned_of_standard_total root ctx role
        (select role) state total).symm

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentSourceSelectorTransport
