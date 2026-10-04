import SmzaRp05HomogeneousExecution

/-! # Same-state fixed-table weights for the homogeneous execution bound -/
namespace HegemonCrypto.SmallWood.SmzaRp05HomogeneousFiberSum

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRoleDomainConditioning SmzaChallengeStageTargets
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRp05DependentAdviceEvent SmzaRp05ConditionedEventJoin
open SmzaRp05HomogeneousExecution SmzaRp05AdaptiveFilteredCollision
open SmzaRp04CompleteRawRoleCells V8Smz9CoherentVectorMerkle
open SmzaRp04RawMcaSampling

noncomputable section
set_option autoImplicit false
set_option exponentiation.threshold 1024

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem records_exactly_fixed_merged_iff_empty
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (fixed : FixedTable ctx blockCap)
    (active : ActiveDatabase ctx blockCap) :
    RecordsExactly (fixedOtherKeys ctx blockCap)
      (mergeFixedActive ctx blockCap fixed active) ↔ active = empty := by
  constructor
  · intro records
    funext key
    cases present : active key with
    | none => rfl
    | some output =>
        have recorded : mergeFixedActive ctx blockCap fixed active key.val = some output :=
          (merge_fixed_active_at_active ctx blockCap fixed active key).trans present
        have member := (records key.val).mp ⟨output, recorded⟩
        exact False.elim (((mem_fixed_other_keys ctx blockCap key.val).mp member) key.property)
  · rintro rfl key
    by_cases live : RoleActive ctx.role blockCap ctx.keyBytes key
    · simp [mergeFixedActive, live, mem_fixed_other_keys, FixedOtherRole, empty]
    · simp [mergeFixedActive, live, mem_fixed_other_keys, FixedOtherRole]

/-- Register state in each initial fixed fiber. The uniform amplitude is
retained here; it is never divided out when applying a per-fiber bound. -/
def initialFiberRegisters
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    RegisterBasis (Input := ActiveKey ctx.role blockCap ctx.keyBytes)
      (Phase := VectorOutput Counter) (Workspace := RoutedWork Key Counter BaseWork) → ℂ :=
  fun basis => inverseSqrtOutputCard (Output := VectorOutput Counter) ^
    (fixedOtherKeys ctx blockCap).card *
    activeRegisterEmbed vectorPhaseSystem ctx.role blockCap ctx.keyBytes dummy registers
      ((registerWorkspaceEquiv (activeMemoryEquiv ctx)).symm basis)

theorem routed_physical_initial_eq_empty_fiber
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    routedPhysicalFiber ctx blockCap dummy fixed (otherRoleTransform ctx blockCap
      (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)) =
    partialRandomOracleState (Output := VectorOutput Counter) ∅
      (initialFiberRegisters ctx blockCap dummy registers) := by
  rw [other_role_transform_initial]
  funext basis
  by_cases vacant : basis.database = empty
  · simp [routedPhysicalFiber, reindexWorkspaceState, basisWorkspaceEquiv,
      fixedFiberToActive, databaseSlice, partialRandomOracleState, vacant,
      records_exactly_fixed_merged_iff_empty, records_exactly_empty_iff,
      Finset.card_empty, pow_zero, initialFiberRegisters, activeRegisterEmbed,
      registerWorkspaceEquiv, basisRegisters]
  · simp [routedPhysicalFiber, reindexWorkspaceState, basisWorkspaceEquiv,
      fixedFiberToActive, databaseSlice, partialRandomOracleState, vacant,
      records_exactly_fixed_merged_iff_empty, records_exactly_empty_iff,
      activeRegisterEmbed, basisRegisters]

theorem sum_fixed_fiber_norm_squared_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    (∑ fixed : FixedTable ctx blockCap,
      normSquared (routedPhysicalFiber ctx blockCap dummy fixed state)) ≤ normSquared state := by
  have split := dependent_fixed_event_mass_eq_sum_fibers ctx blockCap
    (fun _ _ _ => True) state
  have trueProject (input : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
      workspaceEventProjection (fun _ _ => True) input = input := by
    funext basis
    simp [workspaceEventProjection]
  simp only [trueProject] at split
  calc
    _ = ∑ fixed : FixedTable ctx blockCap,
        normSquared (fixedFiberProjection ctx blockCap fixed state) := by
      apply Finset.sum_congr rfl
      intro fixed _
      rw [routedPhysicalFiber, reindex_workspace_state_norm_squared,
        fixed_fiber_to_active_norm_squared]
    _ = _ := split.symm
    _ ≤ normSquared state := by
      unfold normSquared workspaceEventProjection
      apply Finset.sum_le_sum
      intro basis _
      split
      · exact le_rfl
      · simpa using Complex.normSq_nonneg (state basis)

/-- Every basis amplitude of the literal transformed vacuum has a complete
fixed table. Thus disintegration preserves, rather than merely bounds, the
total incoming mass. No table-cardinality simplification is needed. -/
theorem initial_fiber_mass_sum_eq
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    (∑ _fixed : FixedTable ctx blockCap,
      normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅
        (initialFiberRegisters ctx blockCap dummy registers))) =
    normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  let state := otherRoleTransform ctx blockCap
    (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers)
  have covered : workspaceEventProjection
      (dependentFixedEvent ctx blockCap (fun _ _ _ => True)) state = state := by
    rw [show state = partialRandomOracleState (Output := VectorOutput Counter)
      (fixedOtherKeys ctx blockCap) registers from other_role_transform_initial ctx blockCap registers]
    funext basis
    by_cases exactRecords : RecordsExactly (fixedOtherKeys ctx blockCap) basis.database
    · have populated : ∀ key : SmzaRoleDomainConditioning.FixedOtherKey
          ctx.role blockCap ctx.keyBytes, ∃ output, basis.database key.val = some output := by
        intro key
        exact (exactRecords key.val).mpr ((mem_fixed_other_keys ctx blockCap key.val).mpr key.property)
      let fixed : FixedTable ctx blockCap := fun key => Classical.choose (populated key)
      have fiber : fixedFiber ctx blockCap fixed basis.database :=
        fun key => Classical.choose_spec (populated key)
      have selected : dependentFixedEvent ctx blockCap (fun _ _ _ => True)
          basis.workspace basis.database := ⟨fixed, fiber, trivial⟩
      simp [workspaceEventProjection, selected]
    · simp [workspaceEventProjection, partialRandomOracleState, exactRecords]
  have split := dependent_fixed_event_mass_eq_sum_fibers ctx blockCap
    (fun _ _ _ => True) state
  rw [covered] at split
  have trueProject (input : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
      workspaceEventProjection (fun _ _ => True) input = input := by
    funext basis
    simp [workspaceEventProjection]
  simp only [trueProject] at split
  calc
    _ = ∑ fixed : FixedTable ctx blockCap,
        normSquared (routedPhysicalFiber ctx blockCap dummy fixed state) := by
      apply Finset.sum_congr rfl
      intro fixed _
      rw [show state = otherRoleTransform ctx blockCap
        (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) from rfl,
        routed_physical_initial_eq_empty_fiber]
    _ = ∑ fixed : FixedTable ctx blockCap,
        normSquared (fixedFiberProjection ctx blockCap fixed state) := by
      apply Finset.sum_congr rfl
      intro fixed _
      rw [routedPhysicalFiber, reindex_workspace_state_norm_squared,
        fixed_fiber_to_active_norm_squared]
    _ = normSquared state := split.symm
    _ = _ := other_role_transform_norm_squared ctx blockCap _

/-- Sum of the actual incoming sparse-fiber masses is bounded by the
original physical mass, without evaluating the enormous table cardinality. -/
theorem initial_fiber_mass_sum_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    (∑ _fixed : FixedTable ctx blockCap,
      normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅
        (initialFiberRegisters ctx blockCap dummy registers))) ≤
    normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  exact le_of_eq (initial_fiber_mass_sum_eq ctx blockCap dummy registers)

/-- Family of actual sparse programs, each with the advice read from its
own same-execution fixed table. The bound has one incoming mass, not one
absolute loss per fixed table. The separate physical-run compiler must
identify these program outputs with the routed reached physical state. -/
theorem sum_actual_fixed_program_bad_mass_le
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat) (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (cap finish queries : Nat)
    (program : ∀ fixed : FixedTable ctx blockCap,
      ActualProgram (activeContext ctx blockCap fixed) cap 0 finish queries)
    (queriesLe : queries ≤ cap)
    (registers : RegisterBasis (Input := Key) (Phase := VectorOutput Counter)
      (Workspace := SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)) → ℂ) :
    (∑ fixed : FixedTable ctx blockCap,
      normSquared (adaptiveProject (event (activeContext ctx blockCap fixed)) cap
        (AdaptiveProgram.run (ActualProgram.compile (activeContext ctx blockCap fixed) cap
          (program fixed)) (partialRandomOracleState (Output := VectorOutput Counter) ∅
            (initialFiberRegisters ctx blockCap dummy registers))))) ≤
    (6 * (cap : ℝ)^2 * ((completeRoleLoss ctx.role : Rat) : ℝ) +
      36 * (cap : ℝ)^3 / (2^512 : ℝ)) *
      normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅ registers) := by
  let loss := 6 * (cap : ℝ)^2 * ((completeRoleLoss ctx.role : Rat) : ℝ) +
    36 * (cap : ℝ)^3 / (2^512 : ℝ)
  have lossNonnegative : 0 ≤ loss := by
    have roleNonnegative : 0 ≤ ((completeRoleLoss ctx.role : Rat) : ℝ) := by
      exact_mod_cast complete_role_loss_nonnegative ctx.role
    dsimp [loss]
    positivity
  calc
    _ ≤ ∑ _fixed : FixedTable ctx blockCap,
        loss * normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅
          (initialFiberRegisters ctx blockCap dummy registers)) := by
      apply Finset.sum_le_sum
      intro fixed _
      have weighted := actual_program_bad_mass_le_homogeneous (activeContext ctx blockCap fixed)
        cap finish queries (program fixed) queriesLe
        (initialFiberRegisters ctx blockCap dummy registers)
      have count : (queries : ℝ)^2 ≤ (cap : ℝ)^2 := by
        have counted : (queries : ℝ) ≤ cap := by exact_mod_cast queriesLe
        nlinarith [show (0 : ℝ) ≤ queries by positivity]
      have coefficient : 6 * (queries : ℝ)^2 * localBound ctx cap ≤ loss := by
        calc
          _ ≤ 6 * (cap : ℝ)^2 * localBound ctx cap :=
            mul_le_mul_of_nonneg_right
              (mul_le_mul_of_nonneg_left count (by norm_num))
              (local_bound_nonnegative ctx cap)
          _ = loss := by
            simp only [localBound, loss]
            push_cast
            ring
      refine weighted.trans (mul_le_mul_of_nonneg_right coefficient ?_)
      unfold normSquared
      exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)
    _ = loss * ∑ _fixed : FixedTable ctx blockCap,
        normSquared (partialRandomOracleState (Output := VectorOutput Counter) ∅
          (initialFiberRegisters ctx blockCap dummy registers)) := by rw [Finset.mul_sum]
    _ ≤ _ := mul_le_mul_of_nonneg_left
      (initial_fiber_mass_sum_le ctx blockCap dummy registers) lossNonnegative

end
end HegemonCrypto.SmallWood.SmzaRp05HomogeneousFiberSum
