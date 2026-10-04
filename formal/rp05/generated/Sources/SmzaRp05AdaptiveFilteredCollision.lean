import SmzaRp05FilteredCollision
import HegemonCrypto.CmsAdaptiveClaimBridge
import HegemonCrypto.CmsCompressedOracleUnitary

/-!
# Adaptive authorized-filter collision telescope

Unlike the fixed-filter CMS theorem, this file keeps the authorization set in
the workspace basis throughout the execution.  The local query estimate is a
direct sum of fixed-workspace CMS blocks.  Authorization marks and simulated
writes are uncharged transitions: their kernels have no good-to-bad component.

The auxiliary `CmsClassicalDatabase.query` occurs only inside each fixed
workspace instability proof.  Simulator programming is represented by its
actual local state kernel, not by pretending that it is that classical query.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveFilteredCollision

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFullOperatorProof
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CanonicalBytes
open V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle
open SmzaRecordedTracePath
open SmzaRawDatabaseRecords
open SmzaRp04StatementRecordFilter
open SmzaRp05FilteredReadback
open SmzaRp05FilteredCollision

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest

local instance : DecidableEq RawInput :=
  (inferInstance : LinearOrder RawInput).toDecidableEq

/-! ## A marked coordinate is completely ignored -/

variable {Key Counter : Type*}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]

/-- The strong retained-answer fact: once the raw address at `key` parses to
an authorized statement, *any* two CMS databases equal away from `key` have
identical filtered raw-record relations.  This covers insertion, deletion,
and answer replacement uniformly. -/
theorem filtered_raw_records_eq_of_eq_off_authorized_key
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (keyBytes : Key → RawInput) (counter : Counter) (key : Key)
    (marked : statement ∈ authorized)
    (parsed : globalLeafStatement ns (keyBytes key) = some statement)
    (left right : Database Key (VectorOutput Counter))
    (sameOutside : ∀ other, other ≠ key → left other = right other) :
    filteredRawRecords ns authorized keyBytes counter left =
      filteredRawRecords ns authorized keyBytes counter right := by
  unfold filteredRawRecords outsideAuthorizedRecords authorizedFilter
  ext record
  constructor
  · intro member
    have retained := (Finset.mem_filter.mp member).2
    obtain ⟨source, output, recorded, inputEq, digestEq⟩ :=
      (mem_raw_records_iff keyBytes (vectorOutputBytes counter) left
        record.1 record.2).mp (Finset.mem_filter.mp member).1
    by_cases selected : source = key
    · subst source
      exfalso
      unfold keepOutsideAuthorized at retained
      rw [← inputEq, parsed] at retained
      exact retained marked
    · apply Finset.mem_filter.mpr
      refine ⟨(mem_raw_records_iff keyBytes (vectorOutputBytes counter) right
        record.1 record.2).mpr ?_, retained⟩
      exact ⟨source, output, (sameOutside source selected) ▸ recorded,
        inputEq, digestEq⟩
  · intro member
    have retained := (Finset.mem_filter.mp member).2
    obtain ⟨source, output, recorded, inputEq, digestEq⟩ :=
      (mem_raw_records_iff keyBytes (vectorOutputBytes counter) right
        record.1 record.2).mp (Finset.mem_filter.mp member).1
    by_cases selected : source = key
    · subst source
      exfalso
      unfold keepOutsideAuthorized at retained
      rw [← inputEq, parsed] at retained
      exact retained marked
    · apply Finset.mem_filter.mpr
      refine ⟨(mem_raw_records_iff keyBytes (vectorOutputBytes counter) left
        record.1 record.2).mpr ?_, retained⟩
      exact ⟨source, output, (sameOutside source selected).symm ▸ recorded,
        inputEq, digestEq⟩

theorem filtered_raw_collision_iff_of_eq_off_authorized_key
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (keyBytes : Key → RawInput) (counter : Counter) (key : Key)
    (marked : statement ∈ authorized)
    (parsed : globalLeafStatement ns (keyBytes key) = some statement)
    (left right : Database Key (VectorOutput Counter))
    (sameOutside : ∀ other, other ≠ key → left other = right other) :
    filteredRawCollision ns authorized keyBytes counter left ↔
      filteredRawCollision ns authorized keyBytes counter right := by
  unfold filteredRawCollision
  rw [filtered_raw_records_eq_of_eq_off_authorized_key ns authorized
    statement keyBytes counter key marked parsed left right sameOutside]

/-! ## Workspace-dependent projectors -/

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

abbrev AdaptiveEvent (Input Output Workspace : Type*) :=
  Workspace → Database Input Output → Prop

def adaptiveComplement
    (event : AdaptiveEvent Input Output Workspace) :
    AdaptiveEvent Input Output Workspace :=
  fun workspace database => ¬ event workspace database

/-- Bounded orthogonal projection whose database predicate is selected by the
current classical workspace basis. -/
noncomputable def adaptiveProject
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace := by
  classical
  exact fun basis =>
    if size basis.database ≤ cap ∧ event basis.workspace basis.database then
      state basis
    else 0

theorem adaptive_project_add
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (left right : State Input Output Phase Workspace) :
    adaptiveProject event cap (left + right) =
      adaptiveProject event cap left + adaptiveProject event cap right := by
  funext basis
  by_cases selected : size basis.database ≤ cap ∧
      event basis.workspace basis.database <;>
    simp [adaptiveProject, selected]

theorem adaptive_project_add_complement_eq_bounded_project
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    adaptiveProject event cap state +
        adaptiveProject (adaptiveComplement event) cap state =
      project (fun _ => True) cap state := by
  funext basis
  by_cases bounded : size basis.database ≤ cap
  · by_cases selected : event basis.workspace basis.database <;>
      simp [adaptiveProject, adaptiveComplement, project, bounded, selected]
  · simp [adaptiveProject, adaptiveComplement, project, bounded]

theorem adaptive_project_norm_squared_le
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    normSquared (adaptiveProject event cap state) ≤ normSquared state := by
  unfold normSquared adaptiveProject
  apply Finset.sum_le_sum
  intro basis _
  split_ifs
  · exact le_rfl
  · simpa using Complex.normSq_nonneg (state basis)

theorem adaptive_project_state_norm_le
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    stateNorm (adaptiveProject event cap state) ≤ stateNorm state :=
  state_norm_le_of_norm_squared_le
    (adaptive_project_norm_squared_le event cap state)

theorem adaptive_project_bounded_project
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    adaptiveProject event cap (project (fun _ => True) cap state) =
      adaptiveProject event cap state := by
  funext basis
  by_cases selected : size basis.database ≤ cap ∧
      event basis.workspace basis.database <;>
    simp [adaptiveProject, project, selected]

theorem adaptive_project_strict_project
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    adaptiveProject event cap (strictProject cap state) =
      strictProject cap (adaptiveProject event cap state) := by
  funext basis
  by_cases strict : size basis.database < cap
  · have bounded : size basis.database ≤ cap := Nat.le_of_lt strict
    by_cases selected : event basis.workspace basis.database <;>
      simp [adaptiveProject, strictProject, project, strict, bounded, selected]
  · simp [adaptiveProject, strictProject, project, strict]

theorem adaptive_project_preserves_strict_support
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport cap state) :
    StrictSupport cap (adaptiveProject event cap state) := by
  intro basis atOrAbove
  simp [adaptiveProject, strict basis atOrAbove]

theorem workspace_slice_adaptive_project
    (selected : Workspace)
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    workspaceSlice selected (adaptiveProject event cap state) =
      project (event selected) cap (workspaceSlice selected state) := by
  funext basis
  by_cases same : basis.workspace = selected <;>
    simp [workspaceSlice, adaptiveProject, project, same]

/-- The physical CMS query preserves workspace basis blocks exactly. -/
theorem workspace_slice_query_state
    (system : PhaseSystem Output Phase) (cap : Nat)
    (selected : Workspace) (state : State Input Output Phase Workspace) :
    workspaceSlice selected (queryState system cap state) =
      queryState system cap (workspaceSlice selected state) := by
  funext target
  unfold workspaceSlice queryState
  by_cases targetSame : target.workspace = selected
  · simp only [targetSame, if_true]
    apply Finset.sum_congr rfl
    intro source _
    by_cases sourceSame : source.workspace = selected
    · simp [workspaceSlice, sourceSame]
    · have different : target.workspace ≠ source.workspace := by
        intro same
        exact sourceSame (same.symm.trans targetSame)
      simp [workspaceSlice, sourceSame, kernel, different]
  · simp only [targetSame, if_false]
    symm
    apply Finset.sum_eq_zero
    intro source _
    by_cases sourceSame : source.workspace = selected
    · have different : target.workspace ≠ source.workspace := by
        intro same
        exact targetSame (same.trans sourceSame)
      simp [workspaceSlice, sourceSame, kernel, different]
      intro _ _ selectedTarget
      exact False.elim (targetSame selectedTarget)
    · simp [workspaceSlice, sourceSame]

/-- The good-to-bad component of one ordinary CMS query for a genuinely
workspace-dependent event. -/
def adaptiveProjectedQueryState
    (system : PhaseSystem Output Phase)
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  adaptiveProject event cap
    (queryState system cap
      (adaptiveProject (adaptiveComplement event) cap state))

theorem workspace_slice_adaptive_projected_query_state
    (system : PhaseSystem Output Phase)
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (selected : Workspace) (state : State Input Output Phase Workspace) :
    workspaceSlice selected
        (adaptiveProjectedQueryState system event cap state) =
      projectedQueryState system (event selected) cap
        (workspaceSlice selected state) := by
  unfold adaptiveProjectedQueryState projectedQueryState
  rw [workspace_slice_adaptive_project, workspace_slice_query_state,
    workspace_slice_adaptive_project]
  rfl

/-- Homogeneous local CMS estimate for the adaptive projector.  Orthogonal
workspace blocks are recombined by exact squared norms, so there is no factor
for the number of histories or authorization sets. -/
theorem adaptive_projected_query_norm_squared_le
    (system : PhaseSystem Output Phase)
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) {bound : ℝ}
    (instability : ∀ workspace,
      RealInstabilityBound (event workspace) cap bound) :
    normSquared (adaptiveProjectedQueryState system event cap state) ≤
      6 * bound * normSquared state := by
  rw [← sum_workspace_slice_norm_squared
    (adaptiveProjectedQueryState system event cap state)]
  simp_rw [workspace_slice_adaptive_projected_query_state]
  calc
    (∑ workspace : Workspace,
      normSquared (projectedQueryState system (event workspace) cap
        (workspaceSlice workspace state))) ≤
        ∑ workspace : Workspace,
          6 * bound * normSquared (workspaceSlice workspace state) := by
      apply Finset.sum_le_sum
      intro workspace _
      calc
        normSquared (projectedQueryState system (event workspace) cap
            (workspaceSlice workspace state)) =
            fullProjectedNorm system (event workspace) cap
              (workspaceSlice workspace state) :=
          norm_squared_projected_query_state_eq_full_projected_norm
            system (event workspace) cap (workspaceSlice workspace state)
        _ ≤ 6 * bound * fullSourceNorm (workspaceSlice workspace state) :=
          full_projected_norm_le_source_norm system (event workspace) cap
            (workspaceSlice workspace state) (instability workspace)
        _ = 6 * bound * normSquared (workspaceSlice workspace state) := by
          rw [full_source_norm_eq_norm_squared]
    _ = 6 * bound * normSquared state := by
      rw [← Finset.mul_sum, sum_workspace_slice_norm_squared]

/-- Homogeneous local adaptive query bound. The leakage charge scales with
the incoming state's norm, so orthogonal answer/history branches can be
composed without paying a fresh unit-mass constant per branch. -/
theorem adaptive_one_query_amplitude_homogeneous
    (system : PhaseSystem Output Phase)
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) {bound : ℝ}
    (boundNonnegative : 0 ≤ bound)
    (instability : ∀ workspace,
      RealInstabilityBound (event workspace) cap bound) :
    stateNorm
        (adaptiveProject event cap (cappedQueryState system cap state)) ≤
      stateNorm (adaptiveProject event cap state) +
        Real.sqrt (6 * bound) * stateNorm state := by
  have decomposition :
      adaptiveProject event cap (strictProject cap state) +
          adaptiveProject (adaptiveComplement event) cap
            (strictProject cap state) =
        strictProject cap state := by
    rw [adaptive_project_add_complement_eq_bounded_project]
    exact strict_project_bounded cap state
  have projectedEvolution :
      adaptiveProject event cap (cappedQueryState system cap state) =
        adaptiveProject event cap
            (queryState system cap
              (adaptiveProject event cap (strictProject cap state))) +
          adaptiveProjectedQueryState system event cap
            (strictProject cap state) := by
    unfold cappedQueryState adaptiveProjectedQueryState
    rw [adaptive_project_bounded_project]
    conv_lhs => rw [← decomposition]
    funext basis
    by_cases accepted : size basis.database ≤ cap ∧
        event basis.workspace basis.database
    · simp [adaptiveProject, accepted, queryState, Pi.add_apply,
        add_mul, Finset.sum_add_distrib]
    · simp [adaptiveProject, accepted]
  rw [projectedEvolution]
  apply (state_norm_add_le _ _).trans
  have stable :
      stateNorm
          (adaptiveProject event cap
            (queryState system cap
              (adaptiveProject event cap (strictProject cap state)))) ≤
        stateNorm (adaptiveProject event cap state) := by
    calc
      stateNorm
          (adaptiveProject event cap
            (queryState system cap
              (adaptiveProject event cap (strictProject cap state)))) ≤
          stateNorm
            (queryState system cap
              (adaptiveProject event cap (strictProject cap state))) :=
        adaptive_project_state_norm_le event cap _
      _ ≤ stateNorm (adaptiveProject event cap (strictProject cap state)) :=
        state_norm_le_of_norm_squared_le
          (query_state_contractive_of_strict_support system cap
            (adaptiveProject event cap (strictProject cap state))
            (adaptive_project_preserves_strict_support event cap
              (strictProject cap state) (strict_project_strict_support cap state)))
      _ ≤ stateNorm (adaptiveProject event cap state) := by
        rw [adaptive_project_strict_project]
        exact state_norm_le_of_norm_squared_le
          (strict_project_norm_squared_le cap
            (adaptiveProject event cap state))
  have leakageSquared :
      normSquared
          (adaptiveProjectedQueryState system event cap
            (strictProject cap state)) ≤
        6 * bound * normSquared state := by
    calc
      _ ≤ 6 * bound * normSquared (strictProject cap state) :=
        adaptive_projected_query_norm_squared_le system event cap
          (strictProject cap state) instability
      _ ≤ 6 * bound * normSquared state :=
        mul_le_mul_of_nonneg_left
          (strict_project_norm_squared_le cap state)
          (mul_nonneg (by norm_num) boundNonnegative)
  have leakage :
      stateNorm
          (adaptiveProjectedQueryState system event cap
            (strictProject cap state)) ≤
        Real.sqrt (6 * bound) * stateNorm state := by
    have coefficientNonnegative : 0 ≤ 6 * bound :=
      mul_nonneg (by norm_num) boundNonnegative
    have sourceNonnegative := state_norm_nonnegative state
    have targetNonnegative :
        0 ≤ Real.sqrt (6 * bound) * stateNorm state :=
      mul_nonneg (Real.sqrt_nonneg _) sourceNonnegative
    have squared :
        stateNorm (adaptiveProjectedQueryState system event cap
            (strictProject cap state)) ^ 2 ≤
          (Real.sqrt (6 * bound) * stateNorm state) ^ 2 := by
      rw [state_norm_sq_eq_norm_squared, mul_pow,
        Real.sq_sqrt coefficientNonnegative,
        state_norm_sq_eq_norm_squared]
      exact leakageSquared
    nlinarith [state_norm_nonnegative
      (adaptiveProjectedQueryState system event cap
        (strictProject cap state))]
  exact add_le_add stable leakage

/-- One ordinary CMS query increases adaptive bad amplitude by the same local
`sqrt (6*bound)` as a fixed projector.  The proof performs the fixed-property
operator estimate separately on each workspace block and then uses the exact
orthogonal direct sum above. -/
theorem adaptive_one_query_amplitude
    (system : PhaseSystem Output Phase)
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) {bound : ℝ}
    (boundNonnegative : 0 ≤ bound)
    (instability : ∀ workspace,
      RealInstabilityBound (event workspace) cap bound)
    (subnormalized : Subnormalized state) :
    stateNorm
        (adaptiveProject event cap (cappedQueryState system cap state)) ≤
      stateNorm (adaptiveProject event cap state) + Real.sqrt (6 * bound) := by
  have homogeneous := adaptive_one_query_amplitude_homogeneous
    system event cap state boundNonnegative instability
  have sourceNormLeOne : stateNorm state ≤ 1 := by
    have bound := state_norm_le_sqrt state (by norm_num) subnormalized
    simpa using bound
  have coefficientNonnegative : 0 ≤ Real.sqrt (6 * bound) :=
    Real.sqrt_nonneg _
  nlinarith [mul_le_mul_of_nonneg_left
    sourceNormLeOne coefficientNonnegative]

/-! ## Uncharged kernel steps and a variable-projector telescope -/

def kernelApply
    (transition : Basis Input Output Phase Workspace →
      Basis Input Output Phase Workspace → ℂ)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun target => ∑ source, state source * transition source target

theorem kernel_apply_add
    (transition : Basis Input Output Phase Workspace →
      Basis Input Output Phase Workspace → ℂ)
    (left right : State Input Output Phase Workspace) :
    kernelApply transition (left + right) =
      kernelApply transition left + kernelApply transition right := by
  funext target
  unfold kernelApply
  simp [Pi.add_apply, add_mul, Finset.sum_add_distrib]

/-- A kernel supported only on basis pairs transporting `after` back to
`before` has an exactly zero good-to-bad component. -/
theorem kernel_no_good_to_bad
    (before after : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (transition : Basis Input Output Phase Workspace →
      Basis Input Output Phase Workspace → ℂ)
    (support : ∀ source target, transition source target ≠ 0 →
      after target.workspace target.database →
        before source.workspace source.database)
    (state : State Input Output Phase Workspace) :
    adaptiveProject after cap
        (kernelApply transition
          (adaptiveProject (adaptiveComplement before) cap state)) = 0 := by
  funext target
  by_cases accepted : size target.database ≤ cap ∧
      after target.workspace target.database
  · simp only [adaptiveProject, accepted, if_true, kernelApply,
      Pi.zero_apply]
    apply Finset.sum_eq_zero
    intro source _
    by_cases nonzero : transition source target = 0
    · simp [nonzero]
    · have sourceBad := support source target nonzero accepted.2
      by_cases bounded : size source.database ≤ cap
      · simp [adaptiveProject, adaptiveComplement, bounded, sourceBad]
      · simp [adaptiveProject, adaptiveComplement, bounded]
  · simp [adaptiveProject, accepted]

/-- One certified transition between two time-indexed projectors.  `leak` is
an amplitude bound on the local good-to-bad component, not a final execution
probability premise. -/
structure CertifiedAdaptiveStep
    (before after : AdaptiveEvent Input Output Workspace)
    (cap beforeBudget afterBudget : Nat) where
  beforeWithin : beforeBudget ≤ cap
  afterWithin : afterBudget ≤ cap
  apply : State Input Output Phase Workspace → State Input Output Phase Workspace
  leak : ℝ
  leakNonnegative : 0 ≤ leak
  preservesBounded : ∀ {state}, BoundedState beforeBudget state →
    BoundedState afterBudget (apply state)
  preservesSubnormalized : ∀ {state}, Subnormalized state → Subnormalized (apply state)
  amplitude : ∀ state, BoundedState beforeBudget state → Subnormalized state →
    stateNorm (adaptiveProject after cap (apply state)) ≤
      stateNorm (adaptiveProject before cap state) + leak

theorem subnormalized_of_state_norm_le
    {left right : State Input Output Phase Workspace}
    (rightSubnormalized : Subnormalized right)
    (contractive : stateNorm left ≤ stateNorm right) :
    Subnormalized left := by
  unfold Subnormalized at rightSubnormalized ⊢
  have rightSquared : stateNorm right ^ 2 ≤ 1 := by
    rw [state_norm_sq_eq_norm_squared]
    exact rightSubnormalized
  have leftSquared : stateNorm left ^ 2 ≤ 1 := by
    nlinarith [state_norm_nonnegative left, state_norm_nonnegative right]
  rw [← state_norm_sq_eq_norm_squared]
  exact leftSquared

/-- A contractive local kernel with no good-to-bad support is a certified
zero-leak transition between two different time-indexed projectors. -/
def certifiedKernelStep
    (before after : AdaptiveEvent Input Output Workspace)
    (cap beforeBudget afterBudget : Nat)
    (beforeWithin : beforeBudget ≤ cap) (afterWithin : afterBudget ≤ cap)
    (transition : Basis Input Output Phase Workspace →
      Basis Input Output Phase Workspace → ℂ)
    (support : ∀ source target, transition source target ≠ 0 →
      after target.workspace target.database →
        before source.workspace source.database)
    (contractive : ∀ state,
      stateNorm (kernelApply transition state) ≤ stateNorm state)
    (preservesBounded : ∀ {state}, BoundedState beforeBudget state →
      BoundedState afterBudget (kernelApply transition state)) :
    CertifiedAdaptiveStep (Phase := Phase) before after cap beforeBudget afterBudget where
  beforeWithin := beforeWithin
  afterWithin := afterWithin
  apply := kernelApply transition
  leak := 0
  leakNonnegative := le_rfl
  preservesBounded := preservesBounded
  preservesSubnormalized := fun {state} normalized =>
    subnormalized_of_state_norm_le normalized (contractive state)
  amplitude := by
    intro state bounded _
    have boundedAtCap : BoundedState cap state :=
      bounded_state_mono beforeWithin bounded
    have decomposition :
        adaptiveProject before cap state +
            adaptiveProject (adaptiveComplement before) cap state = state := by
      rw [adaptive_project_add_complement_eq_bounded_project]
      exact boundedAtCap
    have applied :
        kernelApply transition state =
          kernelApply transition (adaptiveProject before cap state) +
            kernelApply transition
              (adaptiveProject (adaptiveComplement before) cap state) := by
      rw [← kernel_apply_add, decomposition]
    have noLeak := kernel_no_good_to_bad before after cap transition support state
    rw [applied, adaptive_project_add, noLeak, add_zero]
    simpa using (adaptive_project_state_norm_le after cap _).trans
      (contractive (adaptiveProject before cap state))

/-- One ordinary compressed-oracle query is the charged step.  Its
workspace-dependent local bound was proved above, so this constructor does
not take a search-probability premise. -/
def certifiedOrdinaryQueryStep
    (system : PhaseSystem Output Phase)
    (event : AdaptiveEvent Input Output Workspace) (cap occupied : Nat)
    (room : occupied < cap) {bound : ℝ}
    (boundNonnegative : 0 ≤ bound)
    (instability : ∀ workspace,
      RealInstabilityBound (event workspace) cap bound) :
    CertifiedAdaptiveStep (Phase := Phase) event event cap occupied (occupied + 1) where
  beforeWithin := Nat.le_of_lt room
  afterWithin := Nat.succ_le_iff.mpr room
  apply := cappedQueryState system cap
  leak := Real.sqrt (6 * bound)
  leakNonnegative := Real.sqrt_nonneg _
  preservesBounded := fun {state} bounded => by
    rw [capped_query_state_eq_query_state_of_bounded_lt
      system cap occupied state room bounded]
    exact query_state_bounded_succ_of_bounded
      system cap occupied state room bounded
  preservesSubnormalized := fun {state} normalized =>
    subnormalized_of_state_norm_le normalized
      (capped_query_state_contractive system cap state)
  amplitude := fun state _ normalized =>
    adaptive_one_query_amplitude system event cap state boundNonnegative
      instability normalized

/-- A heterogeneous list keeps the event at every boundary in its type. -/
inductive AdaptiveProgram
    {Phase : Type*} [Fintype Phase] [DecidableEq Phase]
    (cap : Nat) :
    AdaptiveEvent Input Output Workspace → Nat →
      AdaptiveEvent Input Output Workspace → Nat → Type _ where
  | nil {start : AdaptiveEvent Input Output Workspace} {startBudget : Nat} :
      AdaptiveProgram (Phase := Phase) cap start startBudget start startBudget
  | cons {start middle finish startBudget middleBudget finishBudget}
      (step : CertifiedAdaptiveStep (Phase := Phase) start middle cap startBudget middleBudget)
      (remaining : AdaptiveProgram (Phase := Phase) cap middle middleBudget finish finishBudget) :
      AdaptiveProgram (Phase := Phase) cap start startBudget finish finishBudget

namespace AdaptiveProgram

def run {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Workspace} :
    AdaptiveProgram (Phase := Phase) cap start startBudget finish finishBudget →
      State Input Output Phase Workspace → State Input Output Phase Workspace
  | .nil, state => state
  | .cons step remaining, state => run remaining (step.apply state)

def totalLeak {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Workspace} :
    AdaptiveProgram (Phase := Phase) cap start startBudget finish finishBudget → ℝ
  | .nil => 0
  | .cons step remaining => step.leak + totalLeak remaining

theorem run_bounded {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Workspace}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    {state : State Input Output Phase Workspace}
    (bounded : BoundedState startBudget state) :
    BoundedState finishBudget (run program state) := by
  induction program generalizing state with
  | nil => exact bounded
  | cons step remaining ih =>
      exact ih (step.preservesBounded bounded)

theorem run_subnormalized {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Workspace}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    {state : State Input Output Phase Workspace}
    (subnormalized : Subnormalized state) :
    Subnormalized (run program state) := by
  induction program generalizing state with
  | nil => exact subnormalized
  | cons step remaining ih =>
      exact ih (step.preservesSubnormalized subnormalized)

/-- Variable-projector amplitude telescope.  If uncharged mark/write steps
have `leak = 0` and exactly `q` ordinary queries have the common local leak
`δ`, `totalLeak` reduces definitionally/algebraically to `q*δ`; squaring then
gives the CMS form `6*q^2*bound`. -/
theorem amplitude_telescope {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Workspace}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    (state : State Input Output Phase Workspace)
    (bounded : BoundedState startBudget state)
    (subnormalized : Subnormalized state) :
    stateNorm (adaptiveProject finish cap (run program state)) ≤
      stateNorm (adaptiveProject start cap state) + totalLeak program := by
  induction program generalizing state with
  | nil => simp [run, totalLeak]
  | cons step remaining ih =>
      have first := step.amplitude state bounded subnormalized
      have tail := ih (state := step.apply state)
        (step.preservesBounded bounded)
        (step.preservesSubnormalized subnormalized)
      calc
        stateNorm (adaptiveProject _ cap
            (run (.cons step remaining) state)) =
            stateNorm (adaptiveProject _ cap
              (run remaining (step.apply state))) := rfl
        _ ≤ stateNorm (adaptiveProject _ cap (step.apply state)) +
              totalLeak remaining := tail
        _ ≤ (stateNorm (adaptiveProject _ cap state) + step.leak) +
              totalLeak remaining := by nlinarith [first]
        _ = stateNorm (adaptiveProject _ cap state) +
              totalLeak (.cons step remaining) := by
          simp [totalLeak]
          ring

/-- Probability form when exactly `queries` charged steps use the common CMS
local bound and every other step has zero leak. -/
theorem counted_query_probability_bound
    {cap startBudget finishBudget queries : Nat} {bound : ℝ}
    {start finish : AdaptiveEvent Input Output Workspace}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    (state : State Input Output Phase Workspace)
    (bounded : BoundedState startBudget state)
    (subnormalized : Subnormalized state)
    (boundNonnegative : 0 ≤ bound)
    (initiallyGood : adaptiveProject start cap state = 0)
    (counted : totalLeak program =
      (queries : ℝ) * Real.sqrt (6 * bound)) :
    normSquared (adaptiveProject finish cap (run program state)) ≤
      6 * (queries : ℝ) ^ 2 * bound := by
  have amplitude := amplitude_telescope program state bounded subnormalized
  rw [initiallyGood, state_norm_zero, zero_add, counted] at amplitude
  have leftNonnegative := state_norm_nonnegative
    (adaptiveProject finish cap (run program state))
  have rightNonnegative :
      0 ≤ (queries : ℝ) * Real.sqrt (6 * bound) :=
    mul_nonneg (by positivity) (Real.sqrt_nonneg _)
  have squared := mul_self_le_mul_self leftNonnegative amplitude
  calc
    normSquared (adaptiveProject finish cap (run program state)) =
        stateNorm (adaptiveProject finish cap (run program state)) ^ 2 :=
      (state_norm_sq_eq_norm_squared _).symm
    _ ≤ ((queries : ℝ) * Real.sqrt (6 * bound)) ^ 2 := by
      simpa only [pow_two] using squared
    _ = 6 * (queries : ℝ) ^ 2 * bound := by
      rw [mul_pow, Real.sq_sqrt (mul_nonneg (by norm_num) boundNonnegative)]
      ring

end AdaptiveProgram

/-! ## RP05 instantiation of the kernel support condition -/

def workspaceFilteredCollision
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter) :
    AdaptiveEvent Input (VectorOutput Counter) Workspace :=
  fun workspace database =>
    filteredRawCollision ns (authorizedOf workspace)
      keyBytes counter database

/-- Any retained-answer kernel supported on one marked leaf coordinate
transports the adaptive collision event backwards.  The kernel may mix absent
and populated cells and may replace an old answer; no overwrite semantics are
assumed. -/
theorem marked_local_kernel_transports_filtered_collision
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter)
    (source target : Basis Input (VectorOutput Counter) Phase Workspace)
    (sameAuthorization : authorizedOf source.workspace =
      authorizedOf target.workspace)
    (key : Input) (statement : List Byte)
    (marked : statement ∈ authorizedOf target.workspace)
    (parsed : globalLeafStatement ns (keyBytes key) = some statement)
    (sameOutside : ∀ other, other ≠ key →
      source.database other = target.database other)
    (after : workspaceFilteredCollision ns authorizedOf keyBytes counter
      target.workspace target.database) :
    workspaceFilteredCollision ns authorizedOf keyBytes counter
      source.workspace source.database := by
  unfold workspaceFilteredCollision at after ⊢
  rw [sameAuthorization]
  exact (filtered_raw_collision_iff_of_eq_off_authorized_key ns
    (authorizedOf target.workspace) statement keyBytes counter key marked parsed
    source.database target.database sameOutside).mpr after

/-- Pointwise support fact for an authorization mark.  The database is
unchanged and the target workspace adds one statement, so a target collision
already existed under the source authorization set. -/
theorem mark_kernel_transports_filtered_collision
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter)
    (source target : Basis Input (VectorOutput Counter) Phase Workspace)
    (statement : List Byte)
    (authorizationStep : authorizedOf target.workspace =
      Insert.insert statement (authorizedOf source.workspace))
    (sameDatabase : target.database = source.database)
    (after : workspaceFilteredCollision ns authorizedOf keyBytes counter
      target.workspace target.database) :
    workspaceFilteredCollision ns authorizedOf keyBytes counter
      source.workspace source.database := by
  have markedCollision :
      filteredRawCollision ns
        (Insert.insert statement (authorizedOf source.workspace)) keyBytes counter
        source.database := by
    change filteredRawCollision ns (authorizedOf target.workspace)
      keyBytes counter target.database at after
    rw [authorizationStep, sameDatabase] at after
    exact after
  exact filtered_raw_collision_mark_monotone ns
    (authorizedOf source.workspace) statement keyBytes counter source.database
    markedCollision

theorem mark_kernel_no_good_to_bad
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter) (cap : Nat)
    (transition : Basis Input (VectorOutput Counter) Phase Workspace →
      Basis Input (VectorOutput Counter) Phase Workspace → ℂ)
    (localStep : ∀ source target, transition source target ≠ 0 →
      ∃ statement,
        authorizedOf target.workspace =
          Insert.insert statement (authorizedOf source.workspace) ∧
        target.database = source.database)
    (state : State Input (VectorOutput Counter) Phase Workspace) :
    adaptiveProject
        (workspaceFilteredCollision ns authorizedOf keyBytes counter) cap
        (kernelApply transition
          (adaptiveProject
            (adaptiveComplement
              (workspaceFilteredCollision ns authorizedOf keyBytes counter))
            cap state)) = 0 := by
  apply kernel_no_good_to_bad
  intro source target nonzero after
  obtain ⟨statement, authorizationStep, sameDatabase⟩ :=
    localStep source target nonzero
  exact mark_kernel_transports_filtered_collision ns authorizedOf keyBytes
    counter source target statement authorizationStep sameDatabase after

/-- Kernel-level retained-answer specialization.  `local` describes the
literal support of the compression/write/decompression kernel; the conclusion
is the exact zero good-to-bad projector needed by `certifiedKernelStep`. -/
theorem marked_write_kernel_no_good_to_bad
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter) (cap : Nat)
    (transition : Basis Input (VectorOutput Counter) Phase Workspace →
      Basis Input (VectorOutput Counter) Phase Workspace → ℂ)
    (localStep : ∀ source target, transition source target ≠ 0 →
      ∃ key statement,
        authorizedOf source.workspace = authorizedOf target.workspace ∧
        statement ∈ authorizedOf target.workspace ∧
        globalLeafStatement ns (keyBytes key) = some statement ∧
        ∀ other, other ≠ key →
          source.database other = target.database other)
    (state : State Input (VectorOutput Counter) Phase Workspace) :
    adaptiveProject
        (workspaceFilteredCollision ns authorizedOf keyBytes counter) cap
        (kernelApply transition
          (adaptiveProject
            (adaptiveComplement
              (workspaceFilteredCollision ns authorizedOf keyBytes counter))
            cap state)) = 0 := by
  apply kernel_no_good_to_bad
  intro source target nonzero after
  obtain ⟨key, statement, sameAuthorization, marked, parsed, sameOutside⟩ :=
    localStep source target nonzero
  exact marked_local_kernel_transports_filtered_collision ns authorizedOf
    keyBytes counter source target sameAuthorization key statement marked parsed
    sameOutside after

/-- Every workspace block inherits the concrete filtered instability. -/
theorem workspace_filtered_collision_instability
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter) (cap : Nat) :
    ∀ workspace,
      RealInstabilityBound
        (workspaceFilteredCollision ns authorizedOf keyBytes counter workspace)
        cap (((cap : Rat) / (2 ^ 512 : Rat) : Rat) : ℝ) := by
  intro workspace
  exact (filtered_raw_collision_instability ns
    (authorizedOf workspace) keyBytes counter cap).toReal

/-- Concrete charged-step constructor for the RP05 filtered collision event. -/
def filteredCollisionOrdinaryQueryStep
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter) (cap occupied : Nat)
    (room : occupied < cap) :
    CertifiedAdaptiveStep (Phase := VectorOutput Counter)
      (workspaceFilteredCollision ns authorizedOf keyBytes counter)
      (workspaceFilteredCollision ns authorizedOf keyBytes counter)
      cap occupied (occupied + 1) :=
  certifiedOrdinaryQueryStep vectorPhaseSystem
    (workspaceFilteredCollision ns authorizedOf keyBytes counter)
    cap occupied room
    (by positivity)
    (workspace_filtered_collision_instability ns authorizedOf
      keyBytes counter cap)

/-- Concrete zero-leak mark constructor.  The remaining arguments are exact
operator facts—support, contraction/isometry, and support-cap preservation—not
a collision or execution-success premise. -/
def filteredCollisionMarkStep
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter)
    (cap beforeBudget afterBudget : Nat)
    (beforeWithin : beforeBudget ≤ cap) (afterWithin : afterBudget ≤ cap)
    (transition : Basis Input (VectorOutput Counter) Phase Workspace →
      Basis Input (VectorOutput Counter) Phase Workspace → ℂ)
    (localStep : ∀ source target, transition source target ≠ 0 →
      ∃ statement,
        authorizedOf target.workspace =
          Insert.insert statement (authorizedOf source.workspace) ∧
        target.database = source.database)
    (contractive : ∀ state,
      stateNorm (kernelApply transition state) ≤ stateNorm state)
    (preservesBounded : ∀ {state}, BoundedState beforeBudget state →
      BoundedState afterBudget (kernelApply transition state)) :
    CertifiedAdaptiveStep (Phase := Phase)
      (workspaceFilteredCollision ns authorizedOf keyBytes counter)
      (workspaceFilteredCollision ns authorizedOf keyBytes counter)
      cap beforeBudget afterBudget :=
  certifiedKernelStep _ _ cap beforeBudget afterBudget
    beforeWithin afterWithin transition
    (by
      intro source target nonzero after
      obtain ⟨statement, authorizationStep, sameDatabase⟩ :=
        localStep source target nonzero
      exact mark_kernel_transports_filtered_collision ns authorizedOf
        keyBytes counter source target statement authorizationStep sameDatabase after)
    contractive preservesBounded

/-- Concrete zero-leak retained-answer write constructor.  Its support may
mix `none` and `some` at the marked coordinate; equality away from that
coordinate is the only database condition used. -/
def filteredCollisionMarkedWriteStep
    (ns : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Workspace → Finset (List Byte))
    (keyBytes : Input → RawInput) (counter : Counter)
    (cap beforeBudget afterBudget : Nat)
    (beforeWithin : beforeBudget ≤ cap) (afterWithin : afterBudget ≤ cap)
    (transition : Basis Input (VectorOutput Counter) Phase Workspace →
      Basis Input (VectorOutput Counter) Phase Workspace → ℂ)
    (localStep : ∀ source target, transition source target ≠ 0 →
      ∃ key statement,
        authorizedOf source.workspace = authorizedOf target.workspace ∧
        statement ∈ authorizedOf target.workspace ∧
        globalLeafStatement ns (keyBytes key) = some statement ∧
        ∀ other, other ≠ key →
          source.database other = target.database other)
    (contractive : ∀ state,
      stateNorm (kernelApply transition state) ≤ stateNorm state)
    (preservesBounded : ∀ {state}, BoundedState beforeBudget state →
      BoundedState afterBudget (kernelApply transition state)) :
    CertifiedAdaptiveStep (Phase := Phase)
      (workspaceFilteredCollision ns authorizedOf keyBytes counter)
      (workspaceFilteredCollision ns authorizedOf keyBytes counter)
      cap beforeBudget afterBudget :=
  certifiedKernelStep _ _ cap beforeBudget afterBudget
    beforeWithin afterWithin transition
    (by
      intro source target nonzero after
      obtain ⟨key, statement, sameAuthorization, marked, parsed, sameOutside⟩ :=
        localStep source target nonzero
      exact marked_local_kernel_transports_filtered_collision ns authorizedOf
        keyBytes counter source target sameAuthorization key statement marked parsed
        sameOutside after)
    contractive preservesBounded

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveFilteredCollision
