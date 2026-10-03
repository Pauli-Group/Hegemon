import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05ScheduledRoleExecution
import SmzaRp05CertifiedFiberCompilerRun
import SmzaRp05ProgramPhysicalMass
import SmzaRp05CurrentNonchallengeSelectorFiberMass

/-! # Standard-totality of ordinary prefixes and physical branches

This file records the totality facts available before fixed-fiber
disintegration.  Ordinary queries are handled only at their certified support
bound; physical terminal reads preserve standard totality on every branch.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessStandardTotal

open scoped Classical
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05OrdinarySoundnessExecution
open SmzaRp05ScheduledRoleExecution
open SmzaRp05CertifiedFiberCompiler (contraction_bounded)
open SmzaRp05PhysicalTerminalRead
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentNonchallengeSelectorFiberMass
open SmzaRp05CurrentNonchallengeSelectorTransport
open SmzaRp05DependentAdviceEvent
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false
set_option maxRecDepth 10000

variable {Key Counter BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- The ordinary-prefix interpreter preserves standard totality when started
from a state bounded by its current query count. -/
theorem ordinary_run_standard_total
    {cap start finish queries : Nat}
    (program : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) start finish queries)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState start state)
    (total : StandardTotal state) :
    StandardTotal (ordinaryRun program state) := by
  induction program generalizing state with
  | nil budget => exact total
  | query occupied room remaining ih =>
      apply ih
      · have nextBounded : BoundedState (occupied + 1)
            (cappedQueryState vectorPhaseSystem cap state) := by
          rw [capped_query_state_eq_query_state_of_bounded_lt
            vectorPhaseSystem cap occupied state room bounded]
          exact query_state_bounded_succ_of_bounded
            vectorPhaseSystem cap occupied state room bounded
        exact nextBounded
      · intro key
        exact physical_query_standard_at key cap occupied room state bounded
          (total key)
  | privateGate budget within step remaining ih =>
      apply ih
      · exact contraction_bounded step budget bounded
      · intro key
        exact standard_at_private_gate key step state (total key)

/-- In particular, the initialized empty-support oracle purification is
standard-total after any ordinary prefix. -/
theorem initialized_ordinary_run_standard_total
    {cap finish queries : Nat}
    (program : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    StandardTotal (ordinaryRun program
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) :=
  ordinary_run_standard_total program _
    (partial_random_oracle_empty_bounded registers)
    (initial_standard_total registers)

/-- Every leaf of the actual answer-dependent physical interpreter preserves
standard totality. The branch remains the original, unnormalized physical
read branch. -/
theorem physical_run_branch_standard_total
    {Work Result : Type}
    [Fintype Work] [DecidableEq Work]
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode program)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (total : StandardTotal state) :
    StandardTotal (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
      encode decode program branch state) := by
  induction program generalizing state with
  | done result => exact total
  | read raw next ih =>
      cases branch with
      | mk answer remainder =>
          exact ih (decode raw answer) remainder
            (physicalReadBranch (encode raw) answer state)
            (physical_read_branch_standard_total (encode raw) answer state total)

/-- The complement of the fixed other-role domain in the full key space. -/
def activeRoleKeys
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) : Finset Key :=
  Finset.univ.filter (RoleActive ctx.role blockCap ctx.keyBytes)

theorem active_fixed_role_keys_partition
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :
    activeRoleKeys ctx blockCap ∪ fixedOtherKeys ctx blockCap = Finset.univ := by
  classical
  ext key
  by_cases active : RoleActive ctx.role blockCap ctx.keyBytes key
  · simp [activeRoleKeys, fixedOtherKeys, FixedOtherRole, active]
  · simp [activeRoleKeys, fixedOtherKeys, FixedOtherRole, active]

theorem active_fixed_role_keys_disjoint
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) :
    Disjoint (activeRoleKeys ctx blockCap) (fixedOtherKeys ctx blockCap) := by
  rw [Finset.disjoint_left]
  intro key active fixed
  exact (Finset.mem_filter.mp fixed).2 ((Finset.mem_filter.mp active).2)

/-- Finite decompressions over a disjoint union factor in either list order. -/
theorem decompress_finset_union_of_disjoint
    {Output Phase Workspace : Type}
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Workspace] [DecidableEq Workspace]
    (left right : Finset Key) (disjoint : Disjoint left right)
    (state : State Key Output Phase Workspace) :
    HegemonCrypto.CmsOracleSimulation.decompressFinset (left ∪ right) state =
      HegemonCrypto.CmsOracleSimulation.decompressFinset left
        (HegemonCrypto.CmsOracleSimulation.decompressFinset right state) := by
  have perm : (left.toList ++ right.toList).Perm (left ∪ right).toList := by
    apply List.perm_of_nodup_nodup_toFinset_eq
    · apply List.nodup_append.mpr
      refine ⟨left.nodup_toList, right.nodup_toList, ?_⟩
      intro key inLeft other inRight same
      subst other
      exact (Finset.disjoint_left.mp disjoint)
        (Finset.mem_toList.mp inLeft) (Finset.mem_toList.mp inRight)
    · exact (left ∪ right).nodup_toList
    · ext key
      simp
  calc
    HegemonCrypto.CmsOracleSimulation.decompressFinset (left ∪ right) state =
        HegemonCrypto.CmsOracleSimulation.decompressList (left ∪ right).toList state := rfl
    _ = HegemonCrypto.CmsOracleSimulation.decompressList (left.toList ++ right.toList) state :=
      HegemonCrypto.CmsOracleSimulation.decompress_list_perm perm.symm state
    _ = HegemonCrypto.CmsOracleSimulation.decompressFinset left
        (HegemonCrypto.CmsOracleSimulation.decompressFinset right state) := by
      simp [HegemonCrypto.CmsOracleSimulation.decompressFinset,
        HegemonCrypto.CmsOracleSimulation.decompressList, List.foldr_append]

/-- Factor full decompression through the actual fixed-other table, leaving
only active coordinates to decompose afterwards. -/
theorem global_decompress_factors_through_other_role
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    globalDecompress state =
      HegemonCrypto.CmsOracleSimulation.decompressFinset
        (activeRoleKeys ctx blockCap) (otherRoleTransform ctx blockCap state) := by
  change HegemonCrypto.CmsOracleSimulation.decompressFinset
      (Finset.univ : Finset Key) state = _
  have partition := active_fixed_role_keys_partition ctx blockCap
  rw [← partition]
  rw [decompress_finset_union_of_disjoint (activeRoleKeys ctx blockCap)
    (fixedOtherKeys ctx blockCap)
    (active_fixed_role_keys_disjoint ctx blockCap) state]
  rfl

/-- Standard totality on the original state yields raw totality at every
fixed-role coordinate after the literal partial decomposition.  Only the
complementary active-key decompressions are moved across the invariant. -/
theorem fixed_other_coordinate_total_after_transform
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : StandardTotal state)
    (key : FixedOtherKey ctx.role blockCap ctx.keyBytes) :
    TotalAt key.val (otherRoleTransform ctx blockCap state) := by
  have omitted : key.val ∉ (activeRoleKeys ctx blockCap).toList := by
    intro member
    have active := (Finset.mem_filter.mp (Finset.mem_toList.mp member)).2
    exact key.property active
  have factored := global_decompress_factors_through_other_role
    ctx blockCap state
  have fullTotal := total key.val
  rw [factored] at fullTotal
  have twice := total_at_decompress_list_of_not_mem key.val
    (activeRoleKeys ctx blockCap).toList
    (HegemonCrypto.CmsOracleSimulation.decompressFinset
      (activeRoleKeys ctx blockCap) (otherRoleTransform ctx blockCap state))
    omitted fullTotal
  simpa [HegemonCrypto.CmsOracleSimulation.decompressFinset,
    SmzaRp05ConditionedExecution.decompress_list_involutive] using twice

/-- The complete ordinary-prefix then physical-read branch has every
fixed-other coordinate total in the exact partially decompressed state used
by the active-fiber compiler. -/
theorem ordinary_physical_branch_fixed_other_total
    {cap finish queries : Nat} {Result : Type}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode program)
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (key : FixedOtherKey ctx.role blockCap ctx.keyBytes) :
    TotalAt key.val (otherRoleTransform ctx blockCap
      (SmzaRp05PhysicalAcceptedReplayLite.physicalRun encode decode program branch
        (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))) := by
  apply fixed_other_coordinate_total_after_transform
  exact physical_run_branch_standard_total encode decode program branch _
    (initialized_ordinary_run_standard_total ordinaryProgram registers)

/-- Nonzero amplitudes on a state total at every fixed coordinate have a
complete fixed table. -/
theorem fixed_table_exists_of_nonzero_basis
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      TotalAt key.val state)
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (nonzero : state basis ≠ 0) :
    ∃ fixed : FixedTable ctx blockCap, fixedFiber ctx blockCap fixed basis.database := by
  have present : ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      ∃ output, basis.database key.val = some output := by
    intro key
    cases recorded : basis.database key.val with
    | none => exact (nonzero (total key basis recorded)).elim
    | some output => exact ⟨output, rfl⟩
  choose fixed fixedAt using present
  exact ⟨fixed, fixedAt⟩

/-- On a raw-total state, the supported dependent selector projection equals
the unrestricted selector projection: every nonzero basis has a complete
fixed-table fiber. -/
theorem nonchallenge_selector_projection_eq_supported
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (keys : Finset Key)
    (select : (XKey keys → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      TotalAt key.val state) :
    nonchallengeSelectorProjection keys select state =
      workspaceEventProjection
        (dependentFixedEvent ctx blockCap
          (fun _ work database => select (xView keys database) work)) state := by
  funext basis
  unfold nonchallengeSelectorProjection workspaceEventProjection
  by_cases selected : select (xView keys basis.database) basis.workspace
  · by_cases nonzero : state basis = 0
    · simp [selected, nonzero, dependentFixedEvent]
    · obtain ⟨fixed, fiber⟩ := fixed_table_exists_of_nonzero_basis
        ctx blockCap state total basis nonzero
      have dependent : ∃ fixed, fixedFiber ctx blockCap fixed basis.database ∧
          select (xView keys basis.database) basis.workspace :=
        ⟨fixed, fiber, selected⟩
      have selectedFiber : dependentFixedEvent ctx blockCap
          (fun _ work database => select (xView keys database) work)
          basis.workspace basis.database := dependent
      rw [if_pos selected, if_pos selectedFiber]
  · simp [selected, dependentFixedEvent]

/-- Exact original selected mass equals the sum over the literal active
fixed-table fibers after a totality-preserving execution. -/
theorem nonchallenge_selector_mass_eq_active_fiber_sum_of_total
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys,
      SmzaChallengeStageTargets.parseStageQuery (ctx.keyBytes key) = none)
    (select : (XKey keys → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (total : ∀ key : FixedOtherKey ctx.role blockCap ctx.keyBytes,
      TotalAt key.val state) :
    normSquared (nonchallengeSelectorProjection keys select state) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (activeNonchallengeSelectorEvent ctx blockCap keys unrecognized select)
          (fixedFiberToActive ctx blockCap dummy fixed state)) := by
  rw [nonchallenge_selector_projection_eq_supported ctx blockCap keys select state total]
  exact nonchallenge_selector_mass_eq_sum_active_fibers
    ctx blockCap dummy keys unrecognized select state

/-- The preceding equality specializes to each ordinary-prefix plus actual
physical-read branch, with no totality premise supplied by the caller. -/
theorem ordinary_physical_branch_selector_mass_eq_active_fiber_sum
    {cap finish queries : Nat} {Result : Type}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := Counter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches decode program)
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (keys : Finset Key)
    (unrecognized : ∀ key ∈ keys,
      SmzaChallengeStageTargets.parseStageQuery (ctx.keyBytes key) = none)
    (select : (XKey keys → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop) :
    normSquared (nonchallengeSelectorProjection keys select
      (otherRoleTransform ctx blockCap
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun encode decode program branch
          (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers))))) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (activeNonchallengeSelectorEvent ctx blockCap keys unrecognized select)
          (fixedFiberToActive ctx blockCap dummy fixed
            (otherRoleTransform ctx blockCap
              (SmzaRp05PhysicalAcceptedReplayLite.physicalRun encode decode program branch
                (ordinaryRun ordinaryProgram
                  (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)))))) := by
  apply nonchallenge_selector_mass_eq_active_fiber_sum_of_total
  intro key
  exact ordinary_physical_branch_fixed_other_total ordinaryProgram registers encode decode
    program branch ctx blockCap key

end
end HegemonCrypto.SmallWood.SmzaRp05OrdinarySoundnessStandardTotal
