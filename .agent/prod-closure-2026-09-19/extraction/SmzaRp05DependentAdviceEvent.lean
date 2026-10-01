import SmzaRp05ConditionedExecution

/-!
# Dependent earlier-table event on one physical state

The earlier advice is selected by the populated fixed-role coordinates of
the same partially decompressed basis. It is not an external context chosen
after observing the oracle. This exact orthogonal disintegration retains
the reached branch weights and never divides by a success probability.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05DependentAdviceEvent

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05CurrentAdaptiveExecution SmzaRp05ConditionedExecution
open SmzaRoleDomainConditioning
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

theorem fixed_fiber_unique
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (left right : FixedTable ctx blockCap)
    (database : Database Key (VectorOutput Counter))
    (inLeft : fixedFiber ctx blockCap left database)
    (inRight : fixedFiber ctx blockCap right database) : left = right := by
  funext key
  exact Option.some.inj ((inLeft key).symm.trans (inRight key))

/-- Advice is read from this basis's actual fixed-role coordinates. A basis
with an absent fixed coordinate belongs to no total-table fiber. -/
def dependentFixedEvent
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (events : FixedTable ctx blockCap →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop) :
    SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop :=
  fun workspace database =>
    ∃ fixed, fixedFiber ctx blockCap fixed database ∧ events fixed workspace database

/-- Exact dependent-event disintegration on the same state. This is a sum
of actual squared branch amplitudes, not a new uniform draw of advice. -/
theorem dependent_fixed_event_mass_eq_sum_fibers
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (events : FixedTable ctx blockCap →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (workspaceEventProjection (dependentFixedEvent ctx blockCap events) state) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection (events fixed)
          (fixedFiberProjection ctx blockCap fixed state)) := by
  unfold normSquared workspaceEventProjection fixedFiberProjection dependentFixedEvent
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  by_cases selected : ∃ fixed, fixedFiber ctx blockCap fixed basis.database ∧
      events fixed basis.workspace basis.database
  · obtain ⟨fixed, fiber, enabled⟩ := selected
    rw [if_pos ⟨fixed, fiber, enabled⟩]
    rw [Fintype.sum_eq_single fixed]
    · simp [fiber, enabled]
    · intro other different
      have outside : ¬ fixedFiber ctx blockCap other basis.database := by
        intro otherFiber
        exact different (fixed_fiber_unique ctx blockCap other fixed basis.database
          otherFiber fiber)
      simp [outside]
  · rw [if_neg selected]
    simp only [map_zero]
    symm
    apply Finset.sum_eq_zero
    intro fixed _
    by_cases fiber : fixedFiber ctx blockCap fixed basis.database
    · have disabled : ¬ events fixed basis.workspace basis.database :=
        fun enabled => selected ⟨fixed, fiber, enabled⟩
      simp [disabled]
    · simp [fiber]

/-- The same-oracle current-role event uses the existing literal fixed
table decoder in each physical fiber. Thus the nonlinear dependence of
labels on earlier oracle tables is inside the projection being decomposed. -/
def dependentCurrentRoleEvent
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat) :=
  dependentFixedEvent ctx blockCap
    (fun fixed => event (contextAtFixed ctx blockCap fixed))

theorem dependent_current_role_mass_eq_same_state_fibers
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (workspaceEventProjection (dependentCurrentRoleEvent ctx blockCap)
      (otherRoleTransform ctx blockCap state)) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection (event (contextAtFixed ctx blockCap fixed))
          (fixedFiberProjection ctx blockCap fixed
            (otherRoleTransform ctx blockCap state))) := by
  exact dependent_fixed_event_mass_eq_sum_fibers ctx blockCap _ _

/-- Summation on one populated fixed-table fiber is summation on its sparse
active database, with no cardinality factor or renormalization. -/
theorem sum_fixed_fiber_eq_sum_active
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (fixed : FixedTable ctx blockCap)
    (value : Database Key (VectorOutput Counter) → ℝ) :
    (∑ database, if fixedFiber ctx blockCap fixed database then value database else 0) =
      ∑ active : ActiveDatabase ctx blockCap,
        value (mergeFixedActive ctx blockCap fixed active) := by
  rw [← (databaseRoleSplit ctx blockCap).symm.sum_comp
    (fun database => if fixedFiber ctx blockCap fixed database then value database else 0)]
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro active _
  simp only [fixed_fiber_iff_split_fixed, Equiv.apply_symm_apply]
  rw [Fintype.sum_eq_single (fixedSomeTable ctx blockCap fixed)]
  · simp [database_role_split_merge]
  · intro other different
    simp only [if_neg different]

/-- The fixed-fiber restriction is an exact isometry on that fiber. The
original query registers are retained in private route memory. -/
theorem fixed_fiber_to_active_norm_squared
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (fixedFiberToActive ctx blockCap dummy fixed state) =
      normSquared (fixedFiberProjection ctx blockCap fixed state) := by
  rw [normSquared_eq_sum_database_registerNormSquared,
    normSquared_eq_sum_database_registerNormSquared]
  calc
    _ = ∑ active : ActiveDatabase ctx blockCap,
        registerNormSquared
          (databaseSlice state (mergeFixedActive ctx blockCap fixed active)) := by
      apply Finset.sum_congr rfl
      intro active _
      exact active_register_embed_normSquared vectorPhaseSystem ctx.role
        blockCap ctx.keyBytes dummy
        (databaseSlice state (mergeFixedActive ctx blockCap fixed active))
    _ = ∑ database, if fixedFiber ctx blockCap fixed database then
        registerNormSquared (databaseSlice state database) else 0 :=
      (sum_fixed_fiber_eq_sum_active ctx blockCap fixed
        (fun database => registerNormSquared (databaseSlice state database))).symm
    _ = _ := by
      apply Finset.sum_congr rfl
      intro database _
      by_cases fiber : fixedFiber ctx blockCap fixed database
      · simp [fixedFiberProjection, databaseSlice, fiber, registerNormSquared]
      · simp [fixedFiberProjection, databaseSlice, fiber, registerNormSquared]

/-- Literal pullback of a physical event to one sparse active state. The
fixed table is a parameter of this one fiber, not an independently sampled
oracle or a new public context. -/
def activeFiberEvent
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (fixed : FixedTable ctx blockCap)
    (selectedEvent : SmzaRp05CurrentAdaptiveExecution.Work
      (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop) :
    ActiveMemory ctx → ActiveDatabase ctx blockCap → Prop :=
  fun memory active => selectedEvent memory.original.2.2
    (mergeFixedActive ctx blockCap fixed active)

theorem fixed_fiber_to_active_event_projection
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (selectedEvent : SmzaRp05CurrentAdaptiveExecution.Work
      (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    fixedFiberToActive ctx blockCap dummy fixed
        (workspaceEventProjection selectedEvent state) =
      workspaceEventProjection (activeFiberEvent ctx blockCap fixed selectedEvent)
        (fixedFiberToActive ctx blockCap dummy fixed state) := by
  funext basis
  unfold fixedFiberToActive activeRegisterEmbed workspaceEventProjection
    activeFiberEvent databaseSlice
  dsimp only [basisRegisters]
  split <;> simp_all

/-- The dependent physical event is now exactly the sum of event masses on
the actual sparse active states. Applying a QROM theorem still requires the
local instability of this literal pullback event, not of a different event. -/
theorem dependent_event_mass_eq_sum_active_event_masses
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (events : FixedTable ctx blockCap →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := Counter) (BaseWork := BaseWork) →
      Database Key (VectorOutput Counter) → Prop)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork)) :
    normSquared (workspaceEventProjection (dependentFixedEvent ctx blockCap events) state) =
      ∑ fixed : FixedTable ctx blockCap,
        normSquared (workspaceEventProjection
          (activeFiberEvent ctx blockCap fixed (events fixed))
          (fixedFiberToActive ctx blockCap dummy fixed state)) := by
  rw [dependent_fixed_event_mass_eq_sum_fibers]
  apply Finset.sum_congr rfl
  intro fixed _
  rw [← fixed_fiber_to_active_event_projection, fixed_fiber_to_active_norm_squared]
  congr 1
  funext basis
  simp only [fixedFiberProjection, workspaceEventProjection]
  split <;> split <;> rfl

end
end HegemonCrypto.SmallWood.SmzaRp05DependentAdviceEvent
