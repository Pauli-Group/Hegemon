import SmzaRp05AdaptiveFilteredCollision
import Q38WholeViewCmsSemantics
import Q38CmsPhaseDecodeIsometry

/-!
# The actual retained-answer kernel as an adaptive zero-leak step

`Q38WholeViewCmsSemantics.actualPhaseRun` does not write an auxiliary
classical table.  On a randomized `freshInput` branch it keeps `old` in the
outer orthogonal sum and applies

`phaseReplaceReadBranch selected old fresh = D_selected · replace · P_old · D_selected`

to the same persistent CMS database.  This file connects that literal
operator to the variable-projector telescope.  The only locality hypothesis
below is that changing the addressed database coordinate cannot change the
event.  It is the pointwise fact proved for marked RP05 leaves by
`SmzaRp05AdaptiveFilteredCollision` and `SmzaRp05AdaptiveDynamicBad`; it is
not an execution or probability premise.

The support budget is time indexed.  A retained-answer branch maps support
`occupied` to `occupied + 1`, using the already checked support theorem for
the interpreter operator.  No claim is made that an unconstrained write
preserves a fixed cap at its boundary.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AdaptiveKernelInstantiation

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.Q38MeasuredCmsNonleaf
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.SmzaRp05AdaptiveFilteredCollision
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open V8Smz9CoherentVectorMerkle

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false
set_option linter.unnecessarySimpa false

variable {Input Output Phase Workspace : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-! ## Coordinate-local support -/

/-- An adaptive event ignores one addressed database coordinate.  The
workspace is deliberately held fixed: authorization history therefore
remains part of the physical basis rather than being quotiented away. -/
def CoordinateInvariant
    (event : AdaptiveEvent Input Output Workspace) (selected : Input) : Prop :=
  ∀ workspace left right,
    (∀ other, other ≠ selected → left other = right other) →
      (event workspace left ↔ event workspace right)

/-- A state has no amplitude on an adaptive event. -/
def VanishesOn
    (event : AdaptiveEvent Input Output Workspace)
    (state : State Input Output Phase Workspace) : Prop :=
  ∀ basis, event basis.workspace basis.database → state basis = 0

theorem set_coordinate_eq_off
    (database : Database Input Output) (selected : Input)
    (coordinate : Option Output) :
    ∀ other, other ≠ selected →
      setDatabaseCoordinate database selected coordinate other = database other := by
  intro other different
  exact set_database_coordinate_other database different coordinate

theorem adaptive_complement_project_vanishes
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace) :
    VanishesOn event
      (adaptiveProject (adaptiveComplement event) cap state) := by
  intro basis selected
  by_cases bounded : size basis.database ≤ cap
  · simp [adaptiveProject, adaptiveComplement, bounded, selected]
  · simp [adaptiveProject, adaptiveComplement, bounded]

theorem adaptive_project_eq_zero_of_vanishes
    (event : AdaptiveEvent Input Output Workspace) (cap : Nat)
    (state : State Input Output Phase Workspace)
    (vanishes : VanishesOn event state) :
    adaptiveProject event cap state = 0 := by
  funext basis
  by_cases selected : size basis.database ≤ cap ∧
      event basis.workspace basis.database
  · simp [adaptiveProject, selected, vanishes basis selected.2]
  · simp [adaptiveProject, selected]

/-- One CMS decompression reflection is block diagonal in every register and
every database coordinate except `selected`.  Hence an event which ignores
that coordinate remains absent exactly. -/
theorem decompress_at_preserves_vanishing
    (event : AdaptiveEvent Input Output Workspace) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (state : State Input Output Phase Workspace)
    (vanishes : VanishesOn event state) :
    VanishesOn event (decompressAt selected state) := by
  intro target targetEvent
  rw [decompress_at_eq_sum_kernel]
  apply Finset.sum_eq_zero
  intro coordinate _
  let source : Basis Input Output Phase Workspace :=
    { input := target.input
      phase := target.phase
      workspace := target.workspace
      database := setDatabaseCoordinate target.database selected coordinate }
  have sourceEvent : event source.workspace source.database := by
    exact (invariant target.workspace source.database target.database
      (set_coordinate_eq_off target.database selected coordinate)).mpr targetEvent
  have sourceZero : state source = 0 := vanishes source sourceEvent
  simpa [source, sourceZero]

theorem coordinate_projection_preserves_vanishing
    (event : AdaptiveEvent Input Output Workspace)
    (selected : Input) (answer : Output)
    (state : State Input Output Phase Workspace)
    (vanishes : VanishesOn event state) :
    VanishesOn event
      (coordinateEventProjection selected answer state) := by
  intro target targetEvent
  simp [coordinateEventProjection, vanishes target targetEvent]

/-- The standard-coordinate retained-answer replacement changes only the
addressed cell and leaves every workspace basis value untouched. -/
theorem replace_read_branch_preserves_vanishing
    (event : AdaptiveEvent Input Output Workspace) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (old fresh : Output) (state : State Input Output Phase Workspace)
    (vanishes : VanishesOn event state) :
    VanishesOn event
      (fun target =>
        if target.database selected = some fresh then
          state { target with database :=
            setDatabaseCoordinate target.database selected (some old) }
        else 0) := by
  intro target targetEvent
  by_cases installed : target.database selected = some fresh
  · let source : Basis Input Output Phase Workspace :=
      { target with database :=
          setDatabaseCoordinate target.database selected (some old) }
    have sourceEvent : event source.workspace source.database := by
      exact (invariant target.workspace source.database target.database
        (set_coordinate_eq_off target.database selected (some old))).mpr targetEvent
    simp [installed, source, vanishes source sourceEvent]
  · simp [installed]

/-! ## Literal RP05 digest retained-answer branch -/

variable {Work : Type}
variable [Fintype Work] [DecidableEq Work]

abbrev DigestState {Input Work : Type} := ResponseCmsState Input Work

/-- Exact support statement for the operator used by
`actualPhaseRun.freshInput`.  Both decompressions and the replacement are
local at `selected`; in particular, the workspace authorization register is
identical on every contributing source/target pair. -/
theorem phase_replace_preserves_vanishing
    (event : AdaptiveEvent Input DigestRegister Work) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (old fresh : DigestRegister) (state : DigestState (Input := Input) (Work := Work))
    (vanishes : VanishesOn event state) :
    VanishesOn event (phaseReplaceReadBranch selected old fresh state) := by
  rw [phase_replace_read_branch_eq_compressed,
    compressedReplaceReadBranch_eq_selected]
  apply decompress_at_preserves_vanishing event selected invariant
  apply replace_read_branch_preserves_vanishing event selected invariant
  apply coordinate_projection_preserves_vanishing event selected old
  exact decompress_at_preserves_vanishing event selected invariant state vanishes

/-- The literal retained-answer branch has exactly zero good-to-bad
component for any coordinate-invariant, workspace-dependent event. -/
theorem phase_replace_no_good_to_bad
    (event : AdaptiveEvent Input DigestRegister Work) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (cap : Nat) (old fresh : DigestRegister)
    (state : DigestState (Input := Input) (Work := Work)) :
    adaptiveProject event cap
        (phaseReplaceReadBranch selected old fresh
          (adaptiveProject (adaptiveComplement event) cap state)) = 0 := by
  apply adaptive_project_eq_zero_of_vanishes
  apply phase_replace_preserves_vanishing event selected invariant
  exact adaptive_complement_project_vanishes event cap state

/-! ## Linearity and contraction of the actual branch -/

theorem decompress_at_add
    (selected : Input)
    (left right : State Input Output Phase Workspace) :
    decompressAt selected (left + right) =
      decompressAt selected left + decompressAt selected right := by
  funext target
  simp only [decompress_at_eq_sum_kernel, Pi.add_apply, add_mul,
    Finset.sum_add_distrib]

theorem coordinate_projection_add
    (selected : Input) (answer : Output)
    (left right : State Input Output Phase Workspace) :
    coordinateEventProjection selected answer (left + right) =
      coordinateEventProjection selected answer left +
        coordinateEventProjection selected answer right := by
  funext target
  by_cases recorded : target.database selected = some answer <;>
    simp [coordinateEventProjection, recorded]

theorem replace_read_branch_add
    (selected : Input) (old fresh : Output)
    (left right : State Input Output Phase Workspace) :
    (fun target : Basis Input Output Phase Workspace =>
      if target.database selected = some fresh then
        (left + right)
          { input := target.input, phase := target.phase,
            workspace := target.workspace,
            database := setDatabaseCoordinate target.database selected (some old) }
      else 0) =
      (fun target : Basis Input Output Phase Workspace =>
        if target.database selected = some fresh then
          left
            { input := target.input, phase := target.phase,
              workspace := target.workspace,
              database := setDatabaseCoordinate target.database selected (some old) }
        else 0) +
      (fun target : Basis Input Output Phase Workspace =>
        if target.database selected = some fresh then
          right
            { input := target.input, phase := target.phase,
              workspace := target.workspace,
              database := setDatabaseCoordinate target.database selected (some old) }
        else 0) := by
  funext target
  by_cases installed : target.database selected = some fresh <;>
    simp [installed]

/-- Generic one-cell replacement used by the full-vector role oracle. -/
def localReplaceReadBranch
    (selected : Input) (old fresh : Output)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun target =>
    if target.database selected = some fresh then
      state { target with database :=
        setDatabaseCoordinate target.database selected (some old) }
    else 0

/-- Generic compressed retained-answer branch.  It is the same
`D_selected · replace · P_old · D_selected` kernel as the physical digest
interpreter, but permits a full-vector output alphabet. -/
def compressedRetainedBranch
    (selected : Input) (old fresh : Output)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  decompressAt selected
    (localReplaceReadBranch selected old fresh
      (coordinateEventProjection selected old (decompressAt selected state)))

theorem compressed_retained_branch_add
    (selected : Input) (old fresh : Output)
    (left right : State Input Output Phase Workspace) :
    compressedRetainedBranch selected old fresh (left + right) =
      compressedRetainedBranch selected old fresh left +
        compressedRetainedBranch selected old fresh right := by
  unfold compressedRetainedBranch localReplaceReadBranch
  rw [decompress_at_add, coordinate_projection_add,
    replace_read_branch_add, decompress_at_add]

theorem phase_replace_add
    (selected : Input) (old fresh : DigestRegister)
    (left right : DigestState (Input := Input) (Work := Work)) :
    phaseReplaceReadBranch selected old fresh (left + right) =
      phaseReplaceReadBranch selected old fresh left +
        phaseReplaceReadBranch selected old fresh right := by
  simp only [phase_replace_read_branch_eq_compressed,
    compressedReplaceReadBranch_eq_selected]
  rw [decompress_at_add, coordinate_projection_add]
  unfold replaceReadBranch
  rw [replace_read_branch_add, decompress_at_add]

theorem compressed_retained_branch_digest_eq_phase_replace
    (selected : Input) (old fresh : DigestRegister)
    (state : DigestState (Input := Input) (Work := Work)) :
    compressedRetainedBranch selected old fresh state =
      phaseReplaceReadBranch selected old fresh state := by
  rw [phase_replace_read_branch_eq_compressed,
    compressedReplaceReadBranch_eq_selected]
  rfl

/-- A coordinate projector is contractive without a total-database
assumption. -/
theorem coordinate_projection_norm_squared_le
    (selected : Input) (answer : Output)
    (state : State Input Output Phase Workspace) :
    normSquared (coordinateEventProjection selected answer state) ≤
      normSquared state := by
  unfold normSquared coordinateEventProjection
  apply Finset.sum_le_sum
  intro basis _
  by_cases recorded : basis.database selected = some answer
  · simp [recorded]
  · simp [recorded, Complex.normSq_nonneg]

/-- Replacing the already-projected `old` coordinate by `fresh` preserves
the exact squared norm.  This is the partial-isometry component of retained
answer programming. -/
theorem replace_projected_norm_squared
    (selected : Input) (old fresh : Output)
    (state : State Input Output Phase Workspace) :
    normSquared
        ((fun target =>
          if target.database selected = some fresh then
            coordinateEventProjection selected old state
              { target with database :=
                setDatabaseCoordinate target.database selected (some old) }
          else 0)) =
      normSquared (coordinateEventProjection selected old state) := by
  rw [norm_squared_eq_sum_database_fiber_norm selected,
    norm_squared_coordinate_event_projection]
  apply Finset.sum_congr rfl
  intro registerInput _
  apply Finset.sum_congr rfl
  intro phaseValue _
  apply Finset.sum_congr rfl
  intro workspace _
  apply Finset.sum_congr rfl
  intro base _
  rw [EuclideanSpace.norm_sq_eq, Fintype.sum_option]
  simp only [database_fiber_state_apply]
  have absentZero :
      (if ((databaseEquiv (Output := Output) selected).symm (base, none)) selected =
            some fresh then
          coordinateEventProjection selected old state
            { input := registerInput
              phase := phaseValue
              workspace := workspace
              database := setDatabaseCoordinate
                ((databaseEquiv (Output := Output) selected).symm (base, none))
                selected (some old) }
        else 0) = 0 := by
    have absent : (base : Database Input Output) selected = none := base.property
    simp [databaseEquiv_symm_none, absent]
  rw [absentZero]
  simp only [norm_zero, zero_pow (by decide : 2 ≠ 0), zero_add]
  rw [Finset.sum_eq_single fresh]
  · have replaced :
        setDatabaseCoordinate
            ((databaseEquiv (Output := Output) selected).symm
              (base, some fresh)) selected (some old) =
          (databaseEquiv (Output := Output) selected).symm
            (base, some old) := by
      rw [← database_equiv_symm_fiber_eq_set_coordinate]
      apply congrArg (databaseEquiv (Output := Output) selected).symm
      apply Prod.ext
      · simp
      · rfl
    rw [replaced]
    simp [databaseEquiv_symm_some, coordinateEventProjection,
      Complex.sq_norm]
  · intro candidate _ different
    have different' : some candidate ≠ (some fresh : Option Output) := by
      simpa using different
    simp [databaseEquiv_symm_some, different']
  · simp

theorem compressed_retained_branch_norm_squared_eq_projection
    (selected : Input) (old fresh : Output)
    (state : State Input Output Phase Workspace) :
    normSquared (compressedRetainedBranch selected old fresh state) =
      normSquared
        (coordinateEventProjection selected old (decompressAt selected state)) := by
  unfold compressedRetainedBranch localReplaceReadBranch
  rw [decompress_at_preserves_norm_squared]
  exact replace_projected_norm_squared selected old fresh
    (decompressAt selected state)

/-- A generic retained-answer branch can alter occupancy only at its one
addressed key.  This is the full-vector analogue of the checked physical
digest support theorem. -/
theorem compressed_retained_branch_bounded_succ
    (selected : Input) (old fresh : Output) (bound : Nat)
    (state : State Input Output Phase Workspace)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (compressedRetainedBranch selected old fresh state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound + 1
  · simp [project, within]
  · have above : bound + 1 < size target.database := Nat.lt_of_not_ge within
    let coordinate :=
      databaseEquiv (Output := Output) selected target.database
    have databaseEq :
        (databaseEquiv (Output := Output) selected).symm coordinate =
          target.database :=
      Equiv.symm_apply_apply
        (databaseEquiv (Output := Output) selected) target.database
    rcases coordinate with ⟨base, targetCoordinate⟩
    have baseAbove : bound < size base.1 := by
      cases targetCoordinate with
      | none =>
          rw [databaseEquiv_symm_none] at databaseEq
          have sizeEq := congrArg size databaseEq
          omega
      | some output =>
          rw [databaseEquiv_symm_some] at databaseEq
          have sizeEq := congrArg size databaseEq
          have insertedSize := size_insert_of_absent base.1 selected output base.2
          omega
    have sourceFiberZero :
        databaseFiberState state target.input target.phase target.workspace
            selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      apply bounded_state_apply_eq_zero_of_lt bounded
      cases source with
      | none =>
          rw [databaseEquiv_symm_none]
          exact baseAbove
      | some output =>
          rw [databaseEquiv_symm_some,
            size_insert_of_absent base.1 selected output base.2]
          omega
    have decompressedFiberZero :
        databaseFiberState (decompressAt selected state)
            target.input target.phase target.workspace selected base = 0 := by
      rw [database_fiber_state_decompress_at, sourceFiberZero]
      simp
    have projectedFiberZero :
        databaseFiberState
            (coordinateEventProjection selected old (decompressAt selected state))
            target.input target.phase target.workspace selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      by_cases recorded :
          ((databaseEquiv (Output := Output) selected).symm
            (base, source)) selected = some old
      · simp only [coordinateEventProjection, recorded, if_true]
        simpa only [database_fiber_state_apply] using
          congrArg (fun fiber => fiber source) decompressedFiberZero
      · simp [coordinateEventProjection, recorded]
    have replacedFiberZero :
        databaseFiberState
            (localReplaceReadBranch selected old fresh
              (coordinateEventProjection selected old (decompressAt selected state)))
            target.input target.phase target.workspace selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      let sourceDatabase :=
        (databaseEquiv (Output := Output) selected).symm (base, source)
      by_cases selectedFresh : sourceDatabase selected = some fresh
      · have sourceBase :
            (databaseEquiv (Output := Output) selected sourceDatabase).1 = base := by
          have applied := Equiv.apply_symm_apply
            (databaseEquiv (Output := Output) selected) (base, source)
          exact congrArg Prod.fst applied
        have replacedDatabase :
            setDatabaseCoordinate sourceDatabase selected (some old) =
              (databaseEquiv (Output := Output) selected).symm
                (base, some old) := by
          rw [← database_equiv_symm_fiber_eq_set_coordinate, sourceBase]
        simpa [localReplaceReadBranch, sourceDatabase, selectedFresh,
          replacedDatabase, database_fiber_state_apply] using
          congrArg (fun fiber => fiber (some old)) projectedFiberZero
      · simp [localReplaceReadBranch, sourceDatabase, selectedFresh]
    have targetEq :
        ({ input := target.input
           phase := target.phase
           workspace := target.workspace
           database :=
             (databaseEquiv (Output := Output) selected).symm
               (base, targetCoordinate) } :
          Basis Input Output Phase Workspace) = target := by
      cases target
      simp_all
    have targetZero :
        compressedRetainedBranch selected old fresh state target = 0 := by
      unfold compressedRetainedBranch
      rw [← targetEq, decompress_at_apply_coordinate, replacedFiberZero]
      simp
    simp [project, within, targetZero]

/-- Exact squared-norm contraction of the interpreter's retained-answer
branch.  The proof uses the checked selected-coordinate identity, not a
postulated kernel bound. -/
theorem phase_replace_norm_squared_le
    (selected : Input) (old fresh : DigestRegister)
    (state : DigestState (Input := Input) (Work := Work)) :
    normSquared (phaseReplaceReadBranch selected old fresh state) ≤
      normSquared state := by
  rw [phase_replace_read_branch_eq_compressed,
    compressedReplaceReadBranch_eq_selected,
    decompress_at_preserves_norm_squared]
  change normSquared
      ((fun target =>
        if target.database selected = some fresh then
          coordinateEventProjection selected old (decompressAt selected state)
            { target with database :=
              setDatabaseCoordinate target.database selected (some old) }
        else 0)) ≤ normSquared state
  rw [replace_projected_norm_squared]
  exact (coordinate_projection_norm_squared_le selected old
    (decompressAt selected state)).trans_eq
      (decompress_at_preserves_norm_squared selected state)

theorem phase_replace_state_norm_le
    (selected : Input) (old fresh : DigestRegister)
    (state : DigestState (Input := Input) (Work := Work)) :
    stateNorm (phaseReplaceReadBranch selected old fresh state) ≤
      stateNorm state :=
  state_norm_le_of_norm_squared_le
    (phase_replace_norm_squared_le selected old fresh state)

/-! ## Direct telescope constructor -/

/-- One fixed-`old` Kraus branch as a certified local step.  This theorem is
not the complete programming instruction; `retainedOldReplaceStep` below
orthogonally assembles all old-answer branches without a cardinality loss. The
`occupied < cap` premise is the syntactic room check already discharged by
`PhaseSupport`; the operator itself supplies locality, contraction and the
`occupied + 1` support conclusion. -/
def phaseReplaceBranchStep
    (event : AdaptiveEvent Input DigestRegister Work) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (cap occupied : Nat) (room : occupied < cap)
    (old fresh : DigestRegister) :
    CertifiedAdaptiveStep (Phase := DigestRegister)
      event event cap occupied (occupied + 1) where
  beforeWithin := Nat.le_of_lt room
  afterWithin := Nat.succ_le_iff.mpr room
  apply := phaseReplaceReadBranch selected old fresh
  leak := 0
  leakNonnegative := le_rfl
  preservesBounded := fun {state} bounded =>
    phase_replace_read_branch_bounded_succ selected old fresh occupied state bounded
  preservesSubnormalized := fun {state} normalized =>
    subnormalized_of_state_norm_le normalized
      (phase_replace_state_norm_le selected old fresh state)
  amplitude := by
    intro state bounded _
    have boundedAtCap : BoundedState cap state :=
      bounded_state_mono (Nat.le_of_lt room) bounded
    have decomposition :
        adaptiveProject event cap state +
            adaptiveProject (adaptiveComplement event) cap state = state := by
      rw [adaptive_project_add_complement_eq_bounded_project]
      exact boundedAtCap
    have applied :
        phaseReplaceReadBranch selected old fresh state =
          phaseReplaceReadBranch selected old fresh
              (adaptiveProject event cap state) +
            phaseReplaceReadBranch selected old fresh
              (adaptiveProject (adaptiveComplement event) cap state) := by
      rw [← phase_replace_add, decomposition]
    have noLeak := phase_replace_no_good_to_bad event selected invariant cap
      old fresh state
    rw [applied, adaptive_project_add, noLeak, add_zero]
    simpa using (adaptive_project_state_norm_le event cap _).trans
      (phase_replace_state_norm_le selected old fresh
        (adaptiveProject event cap state))

/-! ## The complete retained-old instrument

A single `phaseReplaceReadBranch old` is a Kraus branch.  The actual
state-level transition below stores `old` in an orthogonal workspace
coordinate.  Consequently its norm is the sum of the branch squared norms;
there is no union or cardinality factor for the old-answer register.
-/

abbrev RetainedWorkspace (Answer Work : Type*) := Option Answer × Work

/-- Allocate a fresh retained-answer register in its distinguished `none`
sector.  This is an isometric basis embedding, not a measurement or a
many-to-one workspace update. -/
def allocateRetainedNone
    (state : State Input Output Phase Work) :
    State Input Output Phase (RetainedWorkspace Output Work) :=
  fun target =>
    match target.workspace.1 with
    | none => state
        { input := target.input
          phase := target.phase
          workspace := target.workspace.2
          database := target.database }
    | some _ => 0

def retainedNoneSlice
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    State Input Output Phase Work :=
  fun basis => state
    { input := basis.input
      phase := basis.phase
      workspace := (none, basis.workspace)
      database := basis.database }

/-- Extract one orthogonal retained-answer sector. -/
def retainedSomeSlice
    (old : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    State Input Output Phase Work :=
  fun basis => state
    { input := basis.input
      phase := basis.phase
      workspace := (some old, basis.workspace)
      database := basis.database }

@[simp]
theorem retained_none_slice_allocate
    (state : State Input Output Phase Work) :
    retainedNoneSlice (allocateRetainedNone state) = state := by
  rfl

@[simp]
theorem retained_some_slice_allocate
    (old : Output) (state : State Input Output Phase Work) :
    retainedSomeSlice old (allocateRetainedNone state) = 0 := by
  rfl

/-- Complete randomized programming step for one already sampled `fresh`.
The `none` sector is the input sector; every `some old` sector is exactly the
corresponding checked interpreter branch. -/
def retainedOldReplace
    (selected : Input) (fresh : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    State Input Output Phase (RetainedWorkspace Output Work) :=
  fun target =>
    match target.workspace.1 with
    | none => 0
    | some old =>
        compressedRetainedBranch selected old fresh (retainedNoneSlice state)
          { input := target.input
            phase := target.phase
            workspace := target.workspace.2
            database := target.database }

@[simp]
theorem retained_old_replace_none
    (selected : Input) (fresh : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work))
    (input : Input) (phase : Phase) (work : Work)
    (database : Database Input Output) :
    retainedOldReplace selected fresh state
        { input := input
          phase := phase
          workspace := (none, work)
          database := database } = 0 := by
  rfl

/-- Pointwise interpreter mapping: the `some old` orthogonal sector is
literally the old-answer branch used by `actualPhaseRun`, with no state or
probability equality supplied by a caller. -/
@[simp]
theorem retained_old_replace_some
    (selected : Input) (fresh old : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work))
    (input : Input) (phase : Phase) (work : Work)
    (database : Database Input Output) :
    retainedOldReplace selected fresh state
        { input := input
          phase := phase
          workspace := (some old, work)
          database := database } =
      compressedRetainedBranch selected old fresh (retainedNoneSlice state)
        { input := input
          phase := phase
          workspace := work
          database := database } := by
  rfl

/-- A continuation that does not observe the retained-old register is run
once on every orthogonal old-answer sector and the resulting probabilities
are added.  This is exactly the finite-instrument semantics used by
`actualPhaseRun`. -/
def liftedRetainedContinuation
    (continuation : State Input Output Phase Work → ℝ)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) : ℝ :=
  ∑ old : Output, continuation (retainedSomeSlice old state)

/-- Exact action of the allocated retained-answer instruction on every old
sector.  The input is constructed here in the `none` sector; no caller
supplies an execution equality. -/
theorem retained_some_slice_after_allocated_replace
    (selected : Input) (fresh old : Output)
    (state : State Input Output Phase Work) :
    retainedSomeSlice old
        (retainedOldReplace selected fresh (allocateRetainedNone state)) =
      compressedRetainedBranch selected old fresh state := by
  rfl

/-- Whole-instrument execution identity.  It packages allocation, retained
old outcomes, and an old-insensitive continuation without a branch-count
loss or an assumed coupling. -/
theorem lifted_continuation_after_allocated_replace
    (selected : Input) (fresh : Output)
    (continuation : State Input Output Phase Work → ℝ)
    (state : State Input Output Phase Work) :
    liftedRetainedContinuation continuation
        (retainedOldReplace selected fresh (allocateRetainedNone state)) =
      ∑ old : Output,
        continuation (compressedRetainedBranch selected old fresh state) := by
  unfold liftedRetainedContinuation
  apply Finset.sum_congr rfl
  intro old _
  rw [retained_some_slice_after_allocated_replace]

/-- Digest specialization of the pointwise retained-sector identity.  This
is the literal kernel used by `actualPhaseRun`, not merely an operator with
the same support. -/
@[simp]
theorem retained_old_replace_digest_some_eq_phase_replace
    (selected : Input) (fresh old : DigestRegister)
    (state : ResponseCmsState Input (RetainedWorkspace DigestRegister Work))
    (input : Input) (phase : DigestRegister) (work : Work)
    (database : Database Input DigestRegister) :
    retainedOldReplace selected fresh state
        { input := input
          phase := phase
          workspace := (some old, work)
          database := database } =
      phaseReplaceReadBranch selected old fresh (retainedNoneSlice state)
        { input := input
          phase := phase
          workspace := work
          database := database } := by
  rw [retained_old_replace_some,
    compressed_retained_branch_digest_eq_phase_replace]

def retainedBasisEquiv :
    Basis Input Output Phase (RetainedWorkspace Output Work) ≃
      Option Output × Basis Input Output Phase Work where
  toFun basis :=
    (basis.workspace.1,
      { input := basis.input
        phase := basis.phase
        workspace := basis.workspace.2
        database := basis.database })
  invFun pair :=
    { input := pair.2.input
      phase := pair.2.phase
      workspace := (pair.1, pair.2.workspace)
      database := pair.2.database }
  left_inv basis := by cases basis; rfl
  right_inv pair := by cases pair; rfl

theorem allocate_retained_none_norm_squared
    (state : State Input Output Phase Work) :
    normSquared (allocateRetainedNone state) = normSquared state := by
  unfold normSquared allocateRetainedNone
  rw [← retainedBasisEquiv.symm.sum_comp
    (fun basis => Complex.normSq
      (match basis.workspace.1 with
       | none => state
          { input := basis.input
            phase := basis.phase
            workspace := basis.workspace.2
            database := basis.database }
       | some _ => 0))]
  rw [Fintype.sum_prod_type, Fintype.sum_option]
  simp [retainedBasisEquiv]

theorem allocate_retained_none_bounded
    (bound : Nat) {state : State Input Output Phase Work}
    (bounded : BoundedState bound state) :
    BoundedState bound (allocateRetainedNone state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    cases slot : target.workspace.1 with
    | none =>
        have zero := bounded_state_apply_eq_zero_of_lt bounded
          { input := target.input
            phase := target.phase
            workspace := target.workspace.2
            database := target.database } above
        simp [project, allocateRetainedNone, within, slot, zero]
    | some old => simp [project, allocateRetainedNone, within, slot]

theorem adaptive_project_allocate_retained_none
    (event : AdaptiveEvent Input Output Work) (cap : Nat)
    (state : State Input Output Phase Work) :
    adaptiveProject (fun workspace database => event workspace.2 database) cap
        (allocateRetainedNone state) =
      allocateRetainedNone (adaptiveProject event cap state) := by
  funext target
  cases slot : target.workspace.1 <;>
    simp [adaptiveProject, allocateRetainedNone, slot]

theorem retained_none_slice_add
    (left right : State Input Output Phase (RetainedWorkspace Output Work)) :
    retainedNoneSlice (left + right) =
      retainedNoneSlice left + retainedNoneSlice right := by
  rfl

theorem retained_old_replace_add
    (selected : Input) (fresh : Output)
    (left right : State Input Output Phase (RetainedWorkspace Output Work)) :
    retainedOldReplace selected fresh (left + right) =
      retainedOldReplace selected fresh left +
        retainedOldReplace selected fresh right := by
  funext target
  cases slot : target.workspace.1 <;>
    simp [retainedOldReplace, slot, retained_none_slice_add,
      compressed_retained_branch_add, Pi.add_apply]

/-- Orthogonal decomposition of the complete retained-old update. -/
theorem retained_old_replace_norm_squared
    (selected : Input) (fresh : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    normSquared (retainedOldReplace selected fresh state) =
      ∑ old : Output,
        normSquared
          (compressedRetainedBranch selected old fresh
            (retainedNoneSlice state)) := by
  unfold normSquared
  rw [← retainedBasisEquiv.symm.sum_comp
    (fun basis => Complex.normSq (retainedOldReplace selected fresh state basis))]
  rw [Fintype.sum_prod_type, Fintype.sum_option]
  simp [retainedBasisEquiv, retainedOldReplace, Fintype.sum_prod_type]

/-- The answer projectors are an orthogonal sub-partition even when an
absent standard coordinate is present. -/
theorem coordinate_projection_sum_norm_squared_le
    (selected : Input) (state : State Input Output Phase Work) :
    (∑ answer : Output,
      normSquared (coordinateEventProjection selected answer state)) ≤
      normSquared state := by
  unfold normSquared coordinateEventProjection
  rw [Finset.sum_comm]
  apply Finset.sum_le_sum
  intro basis _
  cases recorded : basis.database selected with
  | none =>
      simp [recorded, Complex.normSq_nonneg]
  | some actual =>
      rw [Finset.sum_eq_single actual]
      · simp [recorded]
      · intro candidate _ different
        simp [recorded, Ne.symm different]
      · simp

/-- The whole retained-old instrument is contractive.  This is the
factor-free replacement for applying a subnormalization estimate separately
to every `old` branch and then summing. -/
theorem retained_old_replace_norm_squared_le
    (selected : Input) (fresh : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    normSquared (retainedOldReplace selected fresh state) ≤
      normSquared state := by
  rw [retained_old_replace_norm_squared]
  simp_rw [compressed_retained_branch_norm_squared_eq_projection]
  calc
    (∑ old : Output,
        normSquared (coordinateEventProjection selected old
          (decompressAt selected (retainedNoneSlice state)))) ≤
        normSquared (decompressAt selected (retainedNoneSlice state)) :=
      coordinate_projection_sum_norm_squared_le selected _
    _ = normSquared (retainedNoneSlice state) :=
      decompress_at_preserves_norm_squared selected _
    _ ≤ normSquared state := by
      unfold normSquared retainedNoneSlice
      rw [← retainedBasisEquiv.symm.sum_comp
        (fun basis => Complex.normSq (state basis))]
      rw [Fintype.sum_prod_type]
      let mass (slot : Option Output) :=
        ∑ basis : Basis Input Output Phase Work,
          Complex.normSq (state (retainedBasisEquiv.symm (slot, basis)))
      have bound : mass none ≤ ∑ slot, mass slot :=
        Finset.single_le_sum (s := Finset.univ) (f := mass)
          (fun slot _ => Finset.sum_nonneg fun _ _ => Complex.normSq_nonneg _)
          (Finset.mem_univ (none : Option Output))
      simpa [mass, retainedBasisEquiv] using bound

theorem retained_old_replace_state_norm_le
    (selected : Input) (fresh : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    stateNorm (retainedOldReplace selected fresh state) ≤ stateNorm state :=
  state_norm_le_of_norm_squared_le
    (retained_old_replace_norm_squared_le selected fresh state)

theorem retained_none_slice_bounded
    (bound : Nat)
    {state : State Input Output Phase (RetainedWorkspace Output Work)}
    (bounded : BoundedState bound state) :
    BoundedState bound (retainedNoneSlice state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    have zero := bounded_state_apply_eq_zero_of_lt bounded
      { input := target.input
        phase := target.phase
        workspace := (none, target.workspace)
        database := target.database } above
    simp [project, retainedNoneSlice, within, zero]

theorem retained_old_replace_bounded_succ
    (selected : Input) (fresh : Output) (bound : Nat)
    {state : State Input Output Phase (RetainedWorkspace Output Work)}
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1) (retainedOldReplace selected fresh state) := by
  have sliced := retained_none_slice_bounded bound bounded
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound + 1
  · simp [project, within]
  · have above : bound + 1 < size target.database := Nat.lt_of_not_ge within
    cases slot : target.workspace.1 with
    | none => simp [project, retainedOldReplace, within, slot]
    | some old =>
        have branchBounded := compressed_retained_branch_bounded_succ
          selected old fresh bound (retainedNoneSlice state) sliced
        have zero := bounded_state_apply_eq_zero_of_lt branchBounded
          { input := target.input
            phase := target.phase
            workspace := target.workspace.2
            database := target.database } above
        simp [project, retainedOldReplace, within, slot, zero]

/-- Allocation followed by the complete retained instruction is contractive
relative to the original (unextended) state. -/
theorem allocated_retained_replace_norm_squared_le
    (selected : Input) (fresh : Output)
    (state : State Input Output Phase Work) :
    normSquared
        (retainedOldReplace selected fresh (allocateRetainedNone state)) ≤
      normSquared state := by
  exact (retained_old_replace_norm_squared_le selected fresh _).trans_eq
    (allocate_retained_none_norm_squared state)

/-- The same concrete allocate-and-program instruction consumes at most one
physical CMS support slot. -/
theorem allocated_retained_replace_bounded_succ
    (selected : Input) (fresh : Output) (bound : Nat)
    {state : State Input Output Phase Work}
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (retainedOldReplace selected fresh (allocateRetainedNone state)) :=
  retained_old_replace_bounded_succ selected fresh bound
    (allocate_retained_none_bounded bound bounded)

def ignoreRetained
    (event : AdaptiveEvent Input Output Work) :
    AdaptiveEvent Input Output (RetainedWorkspace Output Work) :=
  fun workspace database => event workspace.2 database

theorem ignore_retained_coordinate_invariant
    (event : AdaptiveEvent Input Output Work) (selected : Input)
    (invariant : CoordinateInvariant event selected) :
    CoordinateInvariant (ignoreRetained event) selected := by
  intro workspace left right sameOutside
  exact invariant workspace.2 left right sameOutside

theorem retained_none_slice_vanishes
    (event : AdaptiveEvent Input Output Work)
    (state : State Input Output Phase (RetainedWorkspace Output Work))
    (vanishes : VanishesOn (ignoreRetained event) state) :
    VanishesOn event (retainedNoneSlice state) := by
  intro basis selected
  exact vanishes
    { input := basis.input
      phase := basis.phase
      workspace := (none, basis.workspace)
      database := basis.database } selected

theorem retained_old_replace_preserves_vanishing
    (event : AdaptiveEvent Input Output Work) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (fresh : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work))
    (vanishes : VanishesOn (ignoreRetained event) state) :
    VanishesOn (ignoreRetained event)
      (retainedOldReplace selected fresh state) := by
  intro target targetEvent
  cases slot : target.workspace.1 with
  | none => simp [retainedOldReplace, slot]
  | some old =>
      have initialVanishes :=
        retained_none_slice_vanishes event state vanishes
      have first := decompress_at_preserves_vanishing event selected invariant
        (retainedNoneSlice state) initialVanishes
      have second := coordinate_projection_preserves_vanishing event selected old
        (decompressAt selected (retainedNoneSlice state)) first
      have third := replace_read_branch_preserves_vanishing event selected invariant
        old fresh _ second
      have branchVanishes := decompress_at_preserves_vanishing event selected
        invariant _ third
      simp only [retainedOldReplace, slot]
      exact branchVanishes
        { input := target.input, phase := target.phase,
          workspace := target.workspace.2, database := target.database } targetEvent

theorem retained_old_replace_no_good_to_bad
    (event : AdaptiveEvent Input Output Work) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (cap : Nat) (fresh : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    adaptiveProject (ignoreRetained event) cap
        (retainedOldReplace selected fresh
          (adaptiveProject
            (adaptiveComplement (ignoreRetained event)) cap state)) = 0 := by
  apply adaptive_project_eq_zero_of_vanishes
  apply retained_old_replace_preserves_vanishing event selected invariant
  exact adaptive_complement_project_vanishes (ignoreRetained event) cap state

/-- Complete, factor-free programming constructor for the adaptive
telescope.  This—not `phaseReplaceBranchStep` by itself—is the constructor for one
whole fresh-programming instruction. -/
def retainedOldReplaceStep
    (event : AdaptiveEvent Input Output Work) (selected : Input)
    (invariant : CoordinateInvariant event selected)
    (cap occupied : Nat) (room : occupied < cap)
    (fresh : Output) :
    CertifiedAdaptiveStep (Phase := Phase)
      (ignoreRetained event) (ignoreRetained event)
      cap occupied (occupied + 1) where
  beforeWithin := Nat.le_of_lt room
  afterWithin := Nat.succ_le_iff.mpr room
  apply := retainedOldReplace selected fresh
  leak := 0
  leakNonnegative := le_rfl
  preservesBounded := fun {state} bounded =>
    retained_old_replace_bounded_succ selected fresh occupied bounded
  preservesSubnormalized := fun {state} normalized =>
    subnormalized_of_state_norm_le normalized
      (retained_old_replace_state_norm_le selected fresh state)
  amplitude := by
    intro state bounded _
    have boundedAtCap : BoundedState cap state :=
      bounded_state_mono (Nat.le_of_lt room) bounded
    have decomposition :
        adaptiveProject (ignoreRetained event) cap state +
            adaptiveProject
              (adaptiveComplement (ignoreRetained event)) cap state = state := by
      rw [adaptive_project_add_complement_eq_bounded_project]
      exact boundedAtCap
    have applied :
        retainedOldReplace selected fresh state =
          retainedOldReplace selected fresh
              (adaptiveProject (ignoreRetained event) cap state) +
            retainedOldReplace selected fresh
              (adaptiveProject
                (adaptiveComplement (ignoreRetained event)) cap state) := by
      rw [← retained_old_replace_add, decomposition]
    have noLeak := retained_old_replace_no_good_to_bad event selected invariant
      cap fresh state
    rw [applied, adaptive_project_add, noLeak, add_zero]
    simpa using
      (adaptive_project_state_norm_le (ignoreRetained event) cap _).trans
      (retained_old_replace_state_norm_le selected fresh
          (adaptiveProject (ignoreRetained event) cap state))

/-- Explicit full-vector specialization used by the RP05 selected-role CMS.
The entire vector at `selected` is retained as one orthogonal old-answer
coordinate; dummy coordinates are not projected out or charged separately. -/
def vectorRetainedOldReplaceStep
    {Counter : Type} [Fintype Counter] [DecidableEq Counter]
    (event : AdaptiveEvent Input (VectorOutput Counter) Work)
    (selected : Input) (invariant : CoordinateInvariant event selected)
    (cap occupied : Nat) (room : occupied < cap)
    (fresh : VectorOutput Counter) :
    CertifiedAdaptiveStep (Phase := VectorOutput Counter)
      (ignoreRetained event) (ignoreRetained event)
      cap occupied (occupied + 1) :=
  retainedOldReplaceStep event selected invariant cap occupied room fresh

/-! ## Retained lift of an actual certified adaptive continuation -/

/-- Run an existing `AdaptiveProgram` independently on every retained-answer
sector.  The program sees exactly the original `Work`; the retained answer is
only an orthogonal history coordinate and cannot influence its gates. -/
def liftAdaptiveProgramRun
    {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Work}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    State Input Output Phase (RetainedWorkspace Output Work) :=
  fun target =>
    match target.workspace.1 with
    | none =>
        AdaptiveProgram.run program (retainedNoneSlice state)
          { input := target.input
            phase := target.phase
            workspace := target.workspace.2
            database := target.database }
    | some old =>
        AdaptiveProgram.run program (retainedSomeSlice old state)
          { input := target.input
            phase := target.phase
            workspace := target.workspace.2
            database := target.database }

@[simp]
theorem retained_none_slice_lift_adaptive_run
    {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Work}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    retainedNoneSlice (liftAdaptiveProgramRun program state) =
      AdaptiveProgram.run program (retainedNoneSlice state) := by
  rfl

@[simp]
theorem retained_some_slice_lift_adaptive_run
    {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Work}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    (old : Output)
    (state : State Input Output Phase (RetainedWorkspace Output Work)) :
    retainedSomeSlice old (liftAdaptiveProgramRun program state) =
      AdaptiveProgram.run program (retainedSomeSlice old state) := by
  rfl

/-- Concrete program-level assembly: allocate the history slot, execute the
retained full-vector replacement, then run the actual certified continuation
without exposing `old`.  Every sector is definitionally the original
`AdaptiveProgram.run` applied to its physical one-cell branch. -/
theorem retained_program_after_allocated_replace
    {cap startBudget finishBudget : Nat}
    {start finish : AdaptiveEvent Input Output Work}
    (program : AdaptiveProgram (Phase := Phase)
      cap start startBudget finish finishBudget)
    (selected : Input) (fresh old : Output)
    (state : State Input Output Phase Work) :
    retainedSomeSlice old
        (liftAdaptiveProgramRun program
          (retainedOldReplace selected fresh (allocateRetainedNone state))) =
      AdaptiveProgram.run program
        (compressedRetainedBranch selected old fresh state) := by
  rw [retained_some_slice_lift_adaptive_run,
    retained_some_slice_after_allocated_replace]

/-! ## Database-controlled private readback/copy -/

/-- A reversible workspace update selected by the current database basis.
This is the right model for copying a diagonal measured/read value into
private history: the controlling database is retained, and the old workspace
is recoverable through the inverse permutation. -/
def databaseControlledWorkspaceUpdate
    (update : Database Input Output → Workspace ≃ Workspace)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  fun target => state
    { target with workspace :=
        (update target.database).symm target.workspace }

def databaseControlledBasisEquiv
    (update : Database Input Output → Workspace ≃ Workspace) :
    Basis Input Output Phase Workspace ≃ Basis Input Output Phase Workspace where
  toFun basis :=
    { basis with workspace := update basis.database basis.workspace }
  invFun basis :=
    { basis with workspace := (update basis.database).symm basis.workspace }
  left_inv basis := by
    rcases basis with ⟨input, phase, workspace, database⟩
    simp
  right_inv basis := by
    rcases basis with ⟨input, phase, workspace, database⟩
    simp

theorem database_controlled_workspace_update_add
    (update : Database Input Output → Workspace ≃ Workspace)
    (left right : State Input Output Phase Workspace) :
    databaseControlledWorkspaceUpdate update (left + right) =
      databaseControlledWorkspaceUpdate update left +
        databaseControlledWorkspaceUpdate update right := by
  rfl

theorem database_controlled_workspace_update_norm_squared
    (update : Database Input Output → Workspace ≃ Workspace)
    (state : State Input Output Phase Workspace) :
    normSquared (databaseControlledWorkspaceUpdate update state) =
      normSquared state := by
  unfold normSquared databaseControlledWorkspaceUpdate
  change (∑ basis,
      Complex.normSq (state ((databaseControlledBasisEquiv update).symm basis))) = _
  exact (databaseControlledBasisEquiv update).symm.sum_comp
    (fun basis => Complex.normSq (state basis))

theorem database_controlled_workspace_update_state_norm
    (update : Database Input Output → Workspace ≃ Workspace)
    (state : State Input Output Phase Workspace) :
    stateNorm (databaseControlledWorkspaceUpdate update state) =
      stateNorm state := by
  have squares : stateNorm (databaseControlledWorkspaceUpdate update state) ^ 2 =
      stateNorm state ^ 2 := by
    rw [state_norm_sq_eq_norm_squared, state_norm_sq_eq_norm_squared,
      database_controlled_workspace_update_norm_squared]
  nlinarith [state_norm_nonnegative (databaseControlledWorkspaceUpdate update state),
    state_norm_nonnegative state]

theorem database_controlled_workspace_update_bounded
    (update : Database Input Output → Workspace ≃ Workspace)
    (bound : Nat) {state : State Input Output Phase Workspace}
    (bounded : BoundedState bound state) :
    BoundedState bound (databaseControlledWorkspaceUpdate update state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    let source : Basis Input Output Phase Workspace :=
      { target with workspace := (update target.database).symm target.workspace }
    have sourceZero : state source = 0 :=
      bounded_state_apply_eq_zero_of_lt bounded source (by simpa [source] using above)
    simp [project, databaseControlledWorkspaceUpdate, within, source, sourceZero]

/-- Exact event condition for an uncharged private copy.  In RP05 it is
discharged by equality of `authorizedOf`; the remaining private history may
change arbitrarily and is retained reversibly. -/
def WorkspaceUpdatePreserves
    (event : AdaptiveEvent Input Output Workspace)
    (update : Database Input Output → Workspace ≃ Workspace) : Prop :=
  ∀ database workspace,
    event ((update database).symm workspace) database ↔ event workspace database

theorem database_controlled_workspace_update_preserves_vanishing
    (event : AdaptiveEvent Input Output Workspace)
    (update : Database Input Output → Workspace ≃ Workspace)
    (preserves : WorkspaceUpdatePreserves event update)
    (state : State Input Output Phase Workspace)
    (vanishes : VanishesOn event state) :
    VanishesOn event (databaseControlledWorkspaceUpdate update state) := by
  intro target targetEvent
  let source : Basis Input Output Phase Workspace :=
    { target with workspace := (update target.database).symm target.workspace }
  have sourceEvent : event source.workspace source.database :=
    (preserves target.database target.workspace).mpr targetEvent
  exact vanishes source sourceEvent

theorem database_controlled_workspace_update_no_good_to_bad
    (event : AdaptiveEvent Input Output Workspace)
    (update : Database Input Output → Workspace ≃ Workspace)
    (preserves : WorkspaceUpdatePreserves event update)
    (cap : Nat) (state : State Input Output Phase Workspace) :
    adaptiveProject event cap
        (databaseControlledWorkspaceUpdate update
          (adaptiveProject (adaptiveComplement event) cap state)) = 0 := by
  apply adaptive_project_eq_zero_of_vanishes
  apply database_controlled_workspace_update_preserves_vanishing
    event update preserves
  exact adaptive_complement_project_vanishes event cap state

/-- Zero-leak telescope constructor for a database-controlled reversible
private copy.  It consumes no query/support slot. -/
def databaseControlledWorkspaceUpdateStep
    (event : AdaptiveEvent Input Output Workspace)
    (update : Database Input Output → Workspace ≃ Workspace)
    (preserves : WorkspaceUpdatePreserves event update)
    (cap budget : Nat) (within : budget ≤ cap) :
    CertifiedAdaptiveStep (Phase := Phase) event event cap budget budget where
  beforeWithin := within
  afterWithin := within
  apply := databaseControlledWorkspaceUpdate update
  leak := 0
  leakNonnegative := le_rfl
  preservesBounded := fun {state} bounded =>
    database_controlled_workspace_update_bounded update budget bounded
  preservesSubnormalized := fun {state} normalized => by
    unfold Subnormalized at normalized ⊢
    rw [database_controlled_workspace_update_norm_squared]
    exact normalized
  amplitude := by
    intro state bounded _
    have boundedAtCap : BoundedState cap state := bounded_state_mono within bounded
    have decomposition :
        adaptiveProject event cap state +
            adaptiveProject (adaptiveComplement event) cap state = state := by
      rw [adaptive_project_add_complement_eq_bounded_project]
      exact boundedAtCap
    have applied :
        databaseControlledWorkspaceUpdate update state =
          databaseControlledWorkspaceUpdate update
              (adaptiveProject event cap state) +
            databaseControlledWorkspaceUpdate update
              (adaptiveProject (adaptiveComplement event) cap state) := by
      rw [← database_controlled_workspace_update_add, decomposition]
    have noLeak := database_controlled_workspace_update_no_good_to_bad
      event update preserves cap state
    rw [applied, adaptive_project_add, noLeak, add_zero]
    simpa using (adaptive_project_state_norm_le event cap _).trans_eq
      (database_controlled_workspace_update_state_norm update
        (adaptiveProject event cap state))

/-- For the filtered-collision event the private-copy side condition reduces
exactly to preservation of the authorization view; equality of the complete
workspace is neither required nor used. -/
theorem filtered_collision_workspace_update_preserves
    {Counter : Type} [Fintype Counter] [DecidableEq Counter]
    (nameSpace : SmzaRp05LeafNamespace.Namespace)
    (authorizedOf : Work → Finset (List Byte))
    (keyBytes : Input → V8SmzaOracleParser.RawInput) (counter : Counter)
    (update : Database Input (VectorOutput Counter) → Work ≃ Work)
    (preservesAuthorization : ∀ database workspace,
      authorizedOf ((update database).symm workspace) = authorizedOf workspace) :
    WorkspaceUpdatePreserves
      (workspaceFilteredCollision nameSpace authorizedOf keyBytes counter) update := by
  intro database workspace
  unfold workspaceFilteredCollision
  rw [preservesAuthorization database workspace]

/-! ## Reversible authorization marks retain their preimage -/

/-- One local mark register.  `saved = some previous` is an orthogonal
history sector containing the complete pre-mark authorization set.  It is
not a lossy `A ↦ insert statement A` workspace map.  A schedule with many
marks allocates one such coordinate per mark. -/
abbrev MarkWorkspace (Statement Work : Type*) :=
  Finset Statement × Option (Finset Statement) × Work

def reversibleMark
    {Statement Work : Type*} [DecidableEq Statement]
    (statement : Statement) :
    MarkWorkspace Statement Work → MarkWorkspace Statement Work
  | (authorized, none, work) =>
      (insert statement authorized, some authorized, work)
  | (authorized, some previous, work) =>
      if authorized = insert statement previous then
        (previous, none, work)
      else
        (authorized, some previous, work)

theorem reversible_mark_involutive
    {Statement Work : Type*} [DecidableEq Statement]
    (statement : Statement) :
    Function.Involutive
      (reversibleMark (Work := Work) statement) := by
  rintro ⟨authorized, saved, work⟩
  cases saved with
  | none => simp [reversibleMark]
  | some previous =>
      by_cases canonical : authorized = insert statement previous
      · subst authorized
        simp [reversibleMark]
      · simp [reversibleMark, canonical]

def reversibleMarkEquiv
    {Statement Work : Type*} [DecidableEq Statement]
    (statement : Statement) :
    MarkWorkspace Statement Work ≃ MarkWorkspace Statement Work :=
  { toFun := reversibleMark statement
    invFun := reversibleMark statement
    left_inv := reversible_mark_involutive (Work := Work) statement
    right_inv := reversible_mark_involutive (Work := Work) statement }

@[simp]
theorem reversible_mark_from_empty
    {Statement Work : Type*} [DecidableEq Statement]
    (statement : Statement) (authorized : Finset Statement) (work : Work) :
    reversibleMark statement (authorized, none, work) =
      (insert statement authorized, some authorized, work) := by
  rfl

/-- The saved history makes the mark a permutation.  This is the exact
finite-basis fact needed to lift it to a norm-preserving whole-view gate. -/
theorem reversible_mark_sum_comp
    {Statement Work : Type*} [Fintype Statement] [DecidableEq Statement]
    [Fintype Work]
    (statement : Statement) (weight : MarkWorkspace Statement Work → ℝ) :
    (∑ workspace, weight (reversibleMark statement workspace)) =
      ∑ workspace, weight workspace := by
  simpa [reversibleMarkEquiv] using
    (reversibleMarkEquiv (Work := Work) statement).sum_comp weight

variable {Statement HistoryWork : Type*}
variable [Fintype Statement] [DecidableEq Statement]
variable [Fintype HistoryWork] [DecidableEq HistoryWork]

/-- Lift the reversible history update to the actual CMS state without
touching the database, query register, or phase register. -/
def reversibleMarkState
    (statement : Statement)
    (state : State Input Output Phase (MarkWorkspace Statement HistoryWork)) :
    State Input Output Phase (MarkWorkspace Statement HistoryWork) :=
  fun target => state
    { target with workspace := reversibleMark statement target.workspace }

def reversibleMarkBasisEquiv
    (statement : Statement) :
    Basis Input Output Phase (MarkWorkspace Statement HistoryWork) ≃
      Basis Input Output Phase (MarkWorkspace Statement HistoryWork) where
  toFun basis :=
    { basis with workspace := reversibleMark statement basis.workspace }
  invFun basis :=
    { basis with workspace := reversibleMark statement basis.workspace }
  left_inv basis := by
    rcases basis with ⟨input, phase, workspace, database⟩
    change
      ({ input := input
         phase := phase
         workspace := reversibleMark statement
           (reversibleMark statement workspace)
         database := database } :
        Basis Input Output Phase (MarkWorkspace Statement HistoryWork)) = _
    rw [reversible_mark_involutive statement workspace]
  right_inv basis := by
    rcases basis with ⟨input, phase, workspace, database⟩
    change
      ({ input := input
         phase := phase
         workspace := reversibleMark statement
           (reversibleMark statement workspace)
         database := database } :
        Basis Input Output Phase (MarkWorkspace Statement HistoryWork)) = _
    rw [reversible_mark_involutive statement workspace]

theorem reversible_mark_state_add
    (statement : Statement)
    (left right :
      State Input Output Phase (MarkWorkspace Statement HistoryWork)) :
    reversibleMarkState statement (left + right) =
      reversibleMarkState statement left + reversibleMarkState statement right := by
  rfl

/-- Orthogonal history retention makes marking an exact norm-preserving
basis permutation. -/
theorem reversible_mark_state_norm_squared
    (statement : Statement)
    (state : State Input Output Phase (MarkWorkspace Statement HistoryWork)) :
    normSquared (reversibleMarkState statement state) = normSquared state := by
  unfold normSquared reversibleMarkState
  change (∑ basis,
      Complex.normSq (state (reversibleMarkBasisEquiv statement basis))) = _
  exact (reversibleMarkBasisEquiv statement).sum_comp
    (fun basis => Complex.normSq (state basis))

theorem reversible_mark_state_norm
    (statement : Statement)
    (state : State Input Output Phase (MarkWorkspace Statement HistoryWork)) :
    stateNorm (reversibleMarkState statement state) = stateNorm state := by
  have squares : stateNorm (reversibleMarkState statement state) ^ 2 =
      stateNorm state ^ 2 := by
    rw [state_norm_sq_eq_norm_squared, state_norm_sq_eq_norm_squared,
      reversible_mark_state_norm_squared]
  nlinarith [state_norm_nonnegative (reversibleMarkState statement state),
    state_norm_nonnegative state]

/-- Marking consumes no CMS support: the physical database is definitionally
the same on the paired source and target bases. -/
theorem reversible_mark_state_bounded
    (statement : Statement) (bound : Nat)
    {state : State Input Output Phase (MarkWorkspace Statement HistoryWork)}
    (bounded : BoundedState bound state) :
    BoundedState bound (reversibleMarkState statement state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound
  · simp [project, within]
  · have above : bound < size target.database := Nat.lt_of_not_ge within
    let source : Basis Input Output Phase
        (MarkWorkspace Statement HistoryWork) :=
      { target with workspace := reversibleMark statement target.workspace }
    have sourceZero : state source = 0 :=
      bounded_state_apply_eq_zero_of_lt bounded source (by simpa [source] using above)
    simp [project, reversibleMarkState, within, source, sourceZero]

/-- Readback of the forward mark sector.  The previous authorization set is
present in `some authorized`; it is available to the inverse and to later
uncomputation. -/
theorem reversible_mark_state_forward_readback
    (statement : Statement) (authorized : Finset Statement)
    (work : HistoryWork)
    (state : State Input Output Phase (MarkWorkspace Statement HistoryWork))
    (targetInput : Input) (targetPhase : Phase)
    (database : Database Input Output) :
    reversibleMarkState statement state
        { input := targetInput
          phase := targetPhase
          workspace := (insert statement authorized, some authorized, work)
          database := database } =
      state
        { input := targetInput
          phase := targetPhase
          workspace := (authorized, none, work)
          database := database } := by
  simp [reversibleMarkState, reversibleMark]

/-! ## Interpreter identification -/

/-- The generic compressed retained branch specializes to the branch
occurring in the same persistent `actualPhaseRun` execution.  `fresh` is
averaged and `old` is summed outside this operator; neither value is supplied
by a second table. -/
theorem actual_phase_fresh_branch_is_retained_kernel
    (queryBound : Nat) (randomized : Bool)
    (sampler : V8Smz9HonestWholeViewGames.InputSampler Input)
    (next : sampler.Coins → DigestRegister →
      V8Smz9HonestWholeViewGames.Program Input Work)
    (state : DigestState (Input := Input) (Work := Work)) :
    actualPhaseRun queryBound randomized
        (.freshInput sampler next) state =
      uniformAverage fun coins : sampler.Coins =>
        let selected := sampler.input coins
        if randomized then
          uniformAverage fun fresh : DigestRegister =>
            ∑ old : DigestRegister,
              actualPhaseRun queryBound randomized (next coins fresh)
                (compressedRetainedBranch selected old fresh state)
        else
          ∑ old : DigestRegister,
            actualPhaseRun queryBound randomized (next coins old)
              (phaseReadBranch selected old state) := by
  simp_rw [compressed_retained_branch_digest_eq_phase_replace]
  rfl

/-- Final deterministic execution bridge for the real `.freshInput`
constructor.  On its randomized arm, the old-answer sum is exactly the
old-insensitive continuation of one state allocated in the fresh `none`
sector and transformed by the retained full instruction. -/
theorem actual_phase_fresh_input_eq_allocated_retained_execution
    (queryBound : Nat) (randomized : Bool)
    (sampler : V8Smz9HonestWholeViewGames.InputSampler Input)
    (next : sampler.Coins → DigestRegister →
      V8Smz9HonestWholeViewGames.Program Input Work)
    (state : DigestState (Input := Input) (Work := Work)) :
    actualPhaseRun queryBound randomized
        (.freshInput sampler next) state =
      uniformAverage fun coins : sampler.Coins =>
        let selected := sampler.input coins
        if randomized then
          uniformAverage fun fresh : DigestRegister =>
            liftedRetainedContinuation
              (actualPhaseRun queryBound randomized (next coins fresh))
              (retainedOldReplace selected fresh
                (allocateRetainedNone state))
        else
          ∑ old : DigestRegister,
            actualPhaseRun queryBound randomized (next coins old)
              (phaseReadBranch selected old state) := by
  rw [actual_phase_fresh_branch_is_retained_kernel]
  simp_rw [lifted_continuation_after_allocated_replace]

end
end HegemonCrypto.SmallWood.SmzaRp05AdaptiveKernelInstantiation
