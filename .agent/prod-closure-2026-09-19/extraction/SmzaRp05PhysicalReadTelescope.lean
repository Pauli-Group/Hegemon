import SmzaRp05SequentialReadCharge
import SmzaRp05CurrentAdaptiveExecution
import SmzaRp05CurrentFinalEvent
import SmzaRp05RoleReadTotality

/-!
# The homogeneous charge of the actual sequential read instrument

This theorem runs `physicalReadTrace` itself. Its induction derives the
one-step recurrence, support growth, totality and all-answer mass from the
instrument; none is supplied as a desired probability inequality.

The terminal key list may be chosen in an already classical verifier branch.
The theorem does not identify that branch with the live verifier, discharge
the pre-terminal event mass, or condition later advice tables for free.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalReadTelescope

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CanonicalBytes
open SmzaRp05PhysicalTerminalRead SmzaRp05SequentialReadCharge
open SmzaRp05VectorReadCharge SmzaRp05SuffixReadout
open SmzaRp05RoleReadTotality

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

variable {Key Counter Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

/-- Lowering the reachable support cap preserves the same local estimate. -/
theorem real_instability_restrict_cap
    (event : Database Key (Answer (Counter := Counter)) → Prop)
    (small large : Nat) (loss : ℝ) (within : small ≤ large)
    (instability : RealInstabilityBound event large loss) :
    RealInstabilityBound event small loss := by
  constructor
  · refine ⟨instability.1.1, ?_⟩
    intro database before bounded input
    exact instability.1.2 database before (lt_of_lt_of_le bounded within) input
  · refine ⟨instability.2.1, ?_⟩
    intro database before bounded input
    exact instability.2.2 database before (lt_of_lt_of_le bounded within) input

/-- Exact finite-read telescope on the physical state, with one charge per
read and the original incoming norm. Repeated keys remain charged. -/
theorem physical_read_trace_role_amplitude_le
    (keys : List Key) (support cap : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state)
    (total : StandardOn keys state)
    (within : support + keys.length ≤ cap)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (instability : ∀ workspace, RealInstabilityBound (event workspace) cap loss) :
    Real.sqrt (∑ answers : ReadAnswers (Input := Key)
        (Answer (Counter := Counter)) keys,
      normSquared (workspaceEventProjection event
        (physicalReadTrace keys answers state))) ≤
      stateNorm (workspaceEventProjection event state) +
        (keys.length : ℝ) * Real.sqrt (6 * loss) * stateNorm state := by
  induction keys generalizing support state with
  | nil =>
      simp only [ReadAnswers, List.length_nil,
        Nat.cast_zero, zero_mul, add_zero]
      simpa only [Fintype.sum_unique, physicalReadTrace] using
        (le_of_eq (sqrt_norm_squared_eq_state_norm
          (workspaceEventProjection event state)))
  | cons key keys ih =>
      let branch := fun answer : Answer (Counter := Counter) =>
        physicalReadBranch key answer state
      let after := fun answer : Answer (Counter := Counter) =>
        Real.sqrt (∑ answers : ReadAnswers (Input := Key)
            (Answer (Counter := Counter)) keys,
          normSquared (workspaceEventProjection event
            (physicalReadTrace keys answers (branch answer))))
      let before := fun answer : Answer (Counter := Counter) =>
        stateNorm (workspaceEventProjection event (branch answer))
      let source := fun answer : Answer (Counter := Counter) =>
        stateNorm (branch answer)
      have tailWithin : support + 1 + keys.length ≤ cap := by
        simp only [List.length_cons] at within
        omega
      have localBound : ∀ answer,
          after answer ≤ before answer +
            ((keys.length : ℝ) * Real.sqrt (6 * loss)) * source answer := by
        intro answer
        exact ih (support + 1) (branch answer)
          (physical_read_branch_bounded_succ key answer support state bounded)
          (standard_on_physical_read_branch keys key answer state
            (fun selected member => total selected (by simp [member]))) tailWithin
      have aggregate := sqrt_sum_sq_le_of_pointwise after before source
        ((keys.length : ℝ) * Real.sqrt (6 * loss))
        (fun _ => Real.sqrt_nonneg _)
        (fun _ => state_norm_nonnegative _)
        (fun _ => state_norm_nonnegative _)
        (by positivity) localBound
      have afterSq : ∀ answer,
          after answer ^ 2 =
            ∑ answers : ReadAnswers (Input := Key)
                (Answer (Counter := Counter)) keys,
              normSquared (workspaceEventProjection event
                (physicalReadTrace keys answers (branch answer))) := by
        intro answer
        exact Real.sq_sqrt (by
          apply Finset.sum_nonneg
          intro answers _
          unfold normSquared
          exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _)
      have sourceSq : (∑ answer, source answer ^ 2) = normSquared state := by
        simp only [source, state_norm_sq_eq_norm_squared]
        exact sum_physical_read_branch_norm_squared_of_total_at key state
          (total key (by simp))
      have beforeSq : (∑ answer, before answer ^ 2) =
          ∑ answer, normSquared (workspaceEventProjection event (branch answer)) := by
        simp only [before, state_norm_sq_eq_norm_squared]
      simp_rw [afterSq] at aggregate
      rw [sourceSq, beforeSq, sqrt_norm_squared_eq_state_norm] at aggregate
      have one := physical_read_role_amplitude_le_one_query_charge
        key support state bounded (total key (by simp)) event loss lossNonnegative
        (fun workspace => real_instability_restrict_cap
          (event workspace) (support + 1) cap loss (by omega)
          (instability workspace))
      change
        Real.sqrt (∑ answers : Answer (Counter := Counter) ×
            ReadAnswers (Input := Key) (Answer (Counter := Counter)) keys,
          normSquared (workspaceEventProjection event
            (physicalReadTrace (key :: keys) answers state))) ≤ _
      rw [Fintype.sum_prod_type]
      simp only [physicalReadTrace]
      calc
        _ ≤ Real.sqrt (∑ answer,
              normSquared (workspaceEventProjection event (branch answer))) +
            ((keys.length : ℝ) * Real.sqrt (6 * loss)) * stateNorm state :=
          aggregate
        _ ≤ (stateNorm (workspaceEventProjection event state) +
              Real.sqrt (6 * loss) * stateNorm state) +
            ((keys.length : ℝ) * Real.sqrt (6 * loss)) * stateNorm state :=
          add_le_add_left one _
        _ = _ := by
          simp only [List.length_cons, Nat.cast_add, Nat.cast_one]
          ring

/-- The all-answer probability statement is homogeneous in the incoming
state, including zero and subnormalised branches. -/
theorem physical_read_trace_role_mass_le
    (keys : List Key) (support cap : Nat)
    (state : VectorCmsState (Key := Key) (Counter := Counter) (Work := Work))
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + keys.length ≤ cap)
    (event : Work → Database Key (Answer (Counter := Counter)) → Prop)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (instability : ∀ workspace, RealInstabilityBound (event workspace) cap loss) :
    (∑ answers : ReadAnswers (Input := Key)
        (Answer (Counter := Counter)) keys,
      normSquared (workspaceEventProjection event
        (physicalReadTrace keys answers state))) ≤
      (stateNorm (workspaceEventProjection event state) +
        (keys.length : ℝ) * Real.sqrt (6 * loss) * stateNorm state)^2 := by
  have amplitude := physical_read_trace_role_amplitude_le
    keys support cap state bounded total within event loss lossNonnegative instability
  have rightNonnegative : 0 ≤
      stateNorm (workspaceEventProjection event state) +
        (keys.length : ℝ) * Real.sqrt (6 * loss) * stateNorm state :=
    add_nonneg (state_norm_nonnegative _)
      (mul_nonneg (by positivity) (state_norm_nonnegative _))
  have squared := (sq_le_sq₀ (Real.sqrt_nonneg _) rightNonnegative).2 amplitude
  rwa [Real.sq_sqrt (by
    apply Finset.sum_nonneg
    intro answers _
    unfold normSquared
    exact Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _)] at squared

/-- The actual current-role decoder supplies the instability premise. This
is a terminal instrument theorem for each fixed earlier-table context, not
a claim that an arbitrary advice table equals a reached physical table. -/
theorem current_role_physical_read_trace_mass_le
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : SmzaRp05CurrentAdaptiveExecution.Context
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (keys : List Key) (support cap : Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + keys.length ≤ cap) :
    (∑ answers : ReadAnswers (Input := Key)
        (Answer (Counter := Counter)) keys,
      normSquared (workspaceEventProjection
        (SmzaRp05CurrentAdaptiveExecution.event ctx)
        (physicalReadTrace keys answers state))) ≤
      (stateNorm (workspaceEventProjection
          (SmzaRp05CurrentAdaptiveExecution.event ctx) state) +
        (keys.length : ℝ) *
          Real.sqrt (6 * SmzaRp05CurrentAdaptiveExecution.localBound ctx cap) *
          stateNorm state)^2 := by
  exact physical_read_trace_role_mass_le keys support cap state bounded total within
    (SmzaRp05CurrentAdaptiveExecution.event ctx)
    (SmzaRp05CurrentAdaptiveExecution.localBound ctx cap)
    (SmzaRp05CurrentAdaptiveExecution.local_bound_nonnegative ctx cap)
    (SmzaRp05CurrentAdaptiveExecution.event_instability ctx cap)

/-- All four roles are evaluated on the same post-read state. Their local
instabilities are discharged by the current decoder, and the only role
quantities left on the right are on the pre-read state. -/
theorem any_current_role_physical_read_trace_mass_le
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (contexts : SmzaChallengeStageTargets.Role →
      SmzaRp05CurrentAdaptiveExecution.Context
        (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (keys : List Key) (support cap : Nat)
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + keys.length ≤ cap) :
    (∑ answers : ReadAnswers (Input := Key)
        (Answer (Counter := Counter)) keys,
      normSquared (workspaceEventProjection
        (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
        (physicalReadTrace keys answers state))) ≤
      ∑ role : SmzaChallengeStageTargets.Role,
        (stateNorm (workspaceEventProjection
            (SmzaRp05CurrentAdaptiveExecution.event (contexts role)) state) +
          (keys.length : ℝ) *
            Real.sqrt (6 * SmzaRp05CurrentAdaptiveExecution.localBound
              (contexts role) cap) * stateNorm state)^2 := by
  have branchUnion (answers : ReadAnswers (Input := Key)
      (Answer (Counter := Counter)) keys) :
      normSquared (workspaceEventProjection
        (SmzaRp05ConditionedExecution.CertifiedFor.anyContextRoleEvent contexts)
        (physicalReadTrace keys answers state)) ≤
      ∑ role : SmzaChallengeStageTargets.Role,
        normSquared (workspaceEventProjection
          (SmzaRp05CurrentAdaptiveExecution.event (contexts role))
          (physicalReadTrace keys answers state)) := by
    have reached : BoundedState cap (physicalReadTrace keys answers state) :=
      bounded_state_mono within
        (physical_read_trace_bounded_add_length keys answers support state bounded)
    have union :=
      SmzaRp05ConditionedExecution.CertifiedFor.any_context_role_event_mass_le_sum
        contexts cap (physicalReadTrace keys answers state)
    rw [← SmzaRp05VectorReadCharge.workspace_event_eq_adaptive_project_of_bounded
      _ cap _ reached] at union
    simp_rw [← SmzaRp05VectorReadCharge.workspace_event_eq_adaptive_project_of_bounded
      _ cap _ reached] at union
    exact union
  calc
    _ ≤ ∑ answers : ReadAnswers (Input := Key)
          (Answer (Counter := Counter)) keys,
        ∑ role : SmzaChallengeStageTargets.Role,
          normSquared (workspaceEventProjection
            (SmzaRp05CurrentAdaptiveExecution.event (contexts role))
            (physicalReadTrace keys answers state)) :=
      Finset.sum_le_sum fun answers _ => branchUnion answers
    _ = ∑ role : SmzaChallengeStageTargets.Role,
        ∑ answers : ReadAnswers (Input := Key)
            (Answer (Counter := Counter)) keys,
          normSquared (workspaceEventProjection
            (SmzaRp05CurrentAdaptiveExecution.event (contexts role))
            (physicalReadTrace keys answers state)) := Finset.sum_comm
    _ ≤ _ := by
      apply Finset.sum_le_sum
      intro role _
      exact current_role_physical_read_trace_mass_le
        (contexts role) keys support cap state bounded total within

/-- Accepted-failure readout transport with the physical post-read role term
eliminated. This composes the actual finite read instrument, all four current
role decoders, and the selected terminal readout. It does not assume the
desired `roleBudget` inequality from `CurrentFinalEvent`.

This remains the mathematical accepted-failure predicate in that module:
constructing its witness from literal verifier acceptance and identifying
the pre-read execution with the actual source schedule remain separate.
-/
theorem accepted_physical_failure_le_pre_read_amplitudes
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (model : SmzaRp05TracePrefixes.RelationModel)
    (refinement : SmzaRp05AcceptedExtraction.RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : SmzaRp05TracePrefixes.TypedRoutes model Counter)
    (allAdvice : (role : SmzaChallengeStageTargets.Role) →
      SmzaRp05TracePrefixes.AllEarlierTables model role)
    (outerFuel innerFuel cap support : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (state : SmzaRp05CurrentAdaptiveExecution.CmsState
      (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (keys : List Key) (nodup : keys.Nodup)
    (bounded : BoundedState support state) (total : StandardOn keys state)
    (within : support + keys.length ≤ cap) :
    let contexts := SmzaRp05ConditionedExecution.CertifiedFor.roleContexts
      model ns keyBytes counter routes allAdvice outerFuel innerFuel authorizedOf
    SmzaRp05CurrentFinalEvent.acceptedPhysicalSelectedFailureMass
        model refinement ns keyBytes counter routes allAdvice
        outerFuel innerFuel cap authorizedOf state keys ≤
      2 * (∑ role : SmzaChallengeStageTargets.Role,
        (stateNorm (workspaceEventProjection
            (SmzaRp05CurrentAdaptiveExecution.event (contexts role)) state) +
          (keys.length : ℝ) *
            Real.sqrt (6 * SmzaRp05CurrentAdaptiveExecution.localBound
              (contexts role) cap) * stateNorm state)^2) +
      ((2 * (keys.length : ℝ)^2 + 2 * keys.length) /
        Fintype.card (Answer (Counter := Counter))) * normSquared state := by
  dsimp only
  have transported :=
    SmzaRp05CurrentFinalEvent.accepted_physical_selected_failure_mass_transport
      model refinement ns keyBytes counter routes allAdvice
      outerFuel innerFuel cap authorizedOf state keys nodup total
  have roleBound := any_current_role_physical_read_trace_mass_le
    (SmzaRp05ConditionedExecution.CertifiedFor.roleContexts
      model ns keyBytes counter routes allAdvice outerFuel innerFuel authorizedOf)
    keys support cap state bounded total within
  exact transported.trans
    (add_le_add_left (mul_le_mul_of_nonneg_left roleBound
      (show (0 : ℝ) ≤ 2 by norm_num)) _)

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalReadTelescope
