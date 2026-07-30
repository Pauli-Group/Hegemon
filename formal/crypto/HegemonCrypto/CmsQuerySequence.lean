import HegemonCrypto.CmsCompressedOracleUnitary
import Mathlib.Analysis.InnerProductSpace.PiL2
import Mathlib.Tactic.NormNum

/-!
# Finite compressed-oracle query sequences

This module proves the telescoping part of the Chiesa--Manohar--Spooner database lifting lemma in
the same finite state space as `CmsCompressedOracle`.  Inter-query computations are quantified
universally: they may perform any complex-linear contraction on the adversary registers, but may
not inspect or modify the compressed database register.  The resulting theorem has the exact
`6 * q^2 * instability` loss.

`CmsCompressedOracleUnitary` proves that the implemented capped kernel is norm-preserving on the
strict pre-query support reachable before the final query.  The telescope below uses that theorem
directly; norm preservation is not an assumption.
-/

namespace HegemonCrypto.CmsQuerySequence

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsFullOperatorProof
open HegemonCrypto.CmsCompressedOracleUnitary
open HegemonCrypto.DatabaseFiber

noncomputable section

set_option linter.unusedSectionVars false

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

noncomputable local instance complementDecidable
    (property : Property Input Output) :
    DecidablePred (complement property) :=
  Classical.decPred _

/-- The finite state vector, viewed with its genuine Euclidean `l₂` norm. -/
def euclideanState
    (state : State Input Output Phase Workspace) :
    EuclideanSpace ℂ (Basis Input Output Phase Workspace) :=
  WithLp.toLp 2 state

/-- Euclidean norm of a compressed-oracle state. -/
def stateNorm
    (state : State Input Output Phase Workspace) : ℝ :=
  ‖euclideanState state‖

@[simp]
theorem euclidean_state_apply
    (state : State Input Output Phase Workspace)
    (basis : Basis Input Output Phase Workspace) :
    euclideanState state basis = state basis := by
  rfl

/-- The native squared-norm sum is exactly the square of the Euclidean norm. -/
theorem state_norm_sq_eq_norm_squared
    (state : State Input Output Phase Workspace) :
    stateNorm state ^ 2 = normSquared state := by
  unfold stateNorm normSquared
  rw [EuclideanSpace.norm_sq_eq]
  apply Finset.sum_congr rfl
  intro basis _
  exact Complex.sq_norm (state basis)

theorem state_norm_nonnegative
    (state : State Input Output Phase Workspace) :
    0 <= stateNorm state :=
  norm_nonneg _

/-- Euclidean triangle inequality in the finite compressed-oracle state space. -/
theorem state_norm_add_le
    (left right : State Input Output Phase Workspace) :
    stateNorm (left + right) <= stateNorm left + stateNorm right := by
  exact norm_add_le (euclideanState left) (euclideanState right)

theorem state_norm_zero :
    stateNorm (0 : State Input Output Phase Workspace) = 0 := by
  simp [stateNorm, euclideanState]

/-- A squared-norm inequality transfers to the Euclidean norm. -/
theorem state_norm_le_of_norm_squared_le
    {left right : State Input Output Phase Workspace}
    (bound : normSquared left <= normSquared right) :
    stateNorm left <= stateNorm right := by
  have leftNonnegative := state_norm_nonnegative left
  have rightNonnegative := state_norm_nonnegative right
  have squaredBound :
      stateNorm left ^ 2 <= stateNorm right ^ 2 := by
    calc
      stateNorm left ^ 2 = normSquared left :=
        state_norm_sq_eq_norm_squared left
      _ <= normSquared right := bound
      _ = stateNorm right ^ 2 :=
        (state_norm_sq_eq_norm_squared right).symm
  nlinarith

/-- A scalar squared-norm bound transfers to a square-root norm bound. -/
theorem state_norm_le_sqrt
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (boundNonnegative : 0 <= bound)
    (squaredBound : normSquared state <= bound) :
    stateNorm state <= Real.sqrt bound := by
  have normNonnegative := state_norm_nonnegative state
  have sqrtNonnegative := Real.sqrt_nonneg bound
  have sqrtSquare := Real.sq_sqrt boundNonnegative
  rw [← state_norm_sq_eq_norm_squared] at squaredBound
  nlinarith

/-- Coordinate projection is additive. -/
theorem project_add
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (left right : State Input Output Phase Workspace) :
    project property queryBound (left + right) =
      project property queryBound left +
        project property queryBound right := by
  funext basis
  by_cases accepted :
      size basis.database <= queryBound ∧ property basis.database
  · simp [project, accepted]
  · simp [project, accepted]

/-- Nested bounded coordinate projections collapse to the stronger property. -/
theorem project_bounded_project
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    project property queryBound
        (project (fun _database => True) queryBound state) =
      project property queryBound state := by
  funext basis
  by_cases accepted :
      size basis.database <= queryBound ∧ property basis.database
  · simp [project, accepted]
  · simp [project, accepted]

/-- The property and its complement decompose every bounded state exactly. -/
theorem project_add_complement_eq_bounded_project
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    project property queryBound state +
        project (complement property) queryBound state =
      project (fun _database => True) queryBound state := by
  funext basis
  by_cases bounded : size basis.database <= queryBound
  · by_cases accepted : property basis.database
    · simp [project, complement, bounded, accepted]
    · simp [project, complement, bounded, accepted]
  · simp [project, bounded]

/-- A state has no support outside the database-size cap. -/
def BoundedState
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) : Prop :=
  project (fun _database => True) queryBound state = state

/-- A state has squared norm at most one. -/
def Subnormalized
    (state : State Input Output Phase Workspace) : Prop :=
  normSquared state <= 1

/-- Projection onto the strict pre-query support `|D| < t`. -/
def strictProject
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  project (fun database => size database < queryBound) queryBound state

/-- A bounded state has zero amplitude on every database above its bound. -/
theorem bounded_state_apply_eq_zero_of_lt
    {bound : Nat}
    {state : State Input Output Phase Workspace}
    (bounded : BoundedState bound state)
    (basis : Basis Input Output Phase Workspace)
    (above : bound < size basis.database) :
    state basis = 0 := by
  have atBasis := congrFun bounded basis
  have notBounded : ¬ size basis.database <= bound :=
    Nat.not_le.mpr above
  simpa [project, notBounded] using atBasis.symm

/-- A state bounded below `t` has strict pre-query support at `t`. -/
theorem bounded_state_strict_support
    {bound queryBound : Nat}
    {state : State Input Output Phase Workspace}
    (bounded : BoundedState bound state)
    (belowCap : bound < queryBound) :
    StrictSupport queryBound state := by
  intro basis atOrAbove
  exact bounded_state_apply_eq_zero_of_lt bounded basis
    (belowCap.trans_le atOrAbove)

/-- The strict projection has no support at or above the query cap. -/
theorem strict_project_strict_support
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    StrictSupport queryBound (strictProject queryBound state) := by
  intro basis atOrAbove
  have notBelow : ¬ size basis.database < queryBound :=
    Nat.not_lt.mpr atOrAbove
  simp [strictProject, project, notBelow]

/-- Strict projection is the identity on a strictly supported state. -/
theorem strict_project_eq_of_strict_support
    (queryBound : Nat)
    {state : State Input Output Phase Workspace}
    (strict : StrictSupport queryBound state) :
    strictProject queryBound state = state := by
  funext basis
  by_cases below : size basis.database < queryBound
  · have bounded : size basis.database <= queryBound := Nat.le_of_lt below
    simp [strictProject, project, below, bounded]
  · have atOrAbove : queryBound <= size basis.database :=
      Nat.le_of_not_gt below
    rw [strict basis atOrAbove]
    simp [strictProject, project, below]

/-- A state bounded strictly below the query cap is unchanged by strict projection. -/
theorem strict_project_eq_of_bounded_lt
    {bound queryBound : Nat}
    {state : State Input Output Phase Workspace}
    (bounded : BoundedState bound state)
    (belowCap : bound < queryBound) :
    strictProject queryBound state = state :=
  strict_project_eq_of_strict_support queryBound
    (bounded_state_strict_support bounded belowCap)

/-- Strict support is contained in the ordinary bounded database subspace. -/
theorem strict_project_bounded
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    BoundedState queryBound (strictProject queryBound state) := by
  unfold BoundedState strictProject
  funext basis
  by_cases below : size basis.database < queryBound
  · have bounded : size basis.database <= queryBound := Nat.le_of_lt below
    simp [project, below, bounded]
  · simp [project, below]

/-- Coordinate projection preserves strict database support. -/
theorem project_preserves_strict_support
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport queryBound state) :
    StrictSupport queryBound (project property queryBound state) := by
  intro basis atOrAbove
  simp [project, strict basis atOrAbove]

/-- Property projection and strict support projection commute. -/
theorem project_strict_project
    (property : Database Input Output -> Prop)
    [DecidablePred property]
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    project property queryBound (strictProject queryBound state) =
      strictProject queryBound (project property queryBound state) := by
  funext basis
  by_cases below : size basis.database < queryBound
  · have bounded : size basis.database <= queryBound := Nat.le_of_lt below
    by_cases accepted : property basis.database <;>
      simp [strictProject, project, below, bounded, accepted]
  · simp [strictProject, project, below]

/-- Strict projection cannot increase squared norm. -/
theorem strict_project_norm_squared_le
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    normSquared (strictProject queryBound state) <= normSquared state := by
  exact project_norm_squared_le
    (fun database => size database < queryBound) queryBound state

/-- Strict projection preserves subnormalization. -/
theorem strict_project_subnormalized
    (queryBound : Nat)
    {state : State Input Output Phase Workspace}
    (subnormalized : Subnormalized state) :
    Subnormalized (strictProject queryBound state) := by
  exact (strict_project_norm_squared_le queryBound state).trans subnormalized

/--
One implemented compressed-oracle query can add at most one database entry.  The proof is over
the exact active fiber kernel, including fresh insertion, erasure, and replacement branches.
-/
theorem query_state_bounded_succ_of_bounded
    (system : PhaseSystem Output Phase)
    (queryBound bound : Nat)
    (state : State Input Output Phase Workspace)
    (belowCap : bound < queryBound)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1) (queryState system queryBound state) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database <= bound + 1
  · simp [project, within]
  · have above : bound + 1 < size target.database :=
      Nat.lt_of_not_ge within
    have strict : StrictSupport queryBound state :=
      bounded_state_strict_support bounded belowCap
    let coordinate :=
      databaseEquiv (Output := Output) target.input target.database
    have databaseEq :
        (databaseEquiv (Output := Output) target.input).symm coordinate =
          target.database := by
      exact Equiv.symm_apply_apply
        (databaseEquiv (Output := Output) target.input) target.database
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
          have insertedSize :=
            size_insert_of_absent base.1 target.input output base.2
          omega
    have fiberZero :
        stateFiber state target.input target.phase target.workspace base = 0 := by
      ext source
      rw [state_fiber_apply]
      apply bounded_state_apply_eq_zero_of_lt bounded
      cases source with
      | none =>
          rw [databaseEquiv_symm_none]
          exact baseAbove
      | some output =>
          rw [databaseEquiv_symm_some,
            size_insert_of_absent base.1 target.input output base.2]
          omega
    have queryTargetZero :
        queryState system queryBound state target = 0 := by
      have targetEq :
          ({ input := target.input
             phase := target.phase
             workspace := target.workspace
             database :=
               (databaseEquiv (Output := Output) target.input).symm
                 (base, targetCoordinate) } :
            Basis Input Output Phase Workspace) =
            target := by
        cases target
        simp_all
      rw [← targetEq]
      rw [query_state_apply_eq_active_fiber
        system queryBound state strict]
      rw [fiberZero, active_fiber_query_zero_state]
      rfl
    simp [project, within, queryTargetZero]

/-- A support bound remains valid when its numerical cap is enlarged. -/
theorem bounded_state_mono
    {smaller larger : Nat}
    {state : State Input Output Phase Workspace}
    (boundOrder : smaller <= larger)
    (bounded : BoundedState smaller state) :
    BoundedState larger state := by
  unfold BoundedState
  funext basis
  by_cases within : size basis.database <= larger
  · simp [project, within]
  · have aboveLarger : larger < size basis.database :=
      Nat.lt_of_not_ge within
    have aboveSmaller : smaller < size basis.database :=
      lt_of_le_of_lt boundOrder aboveLarger
    have stateZero :=
      bounded_state_apply_eq_zero_of_lt bounded basis aboveSmaller
    simp [project, within, stateZero]

/--
Capping the query output at `t` and its input strictly below `t` realizes the CMS reachable
operator `P_t O P_{<t}`.  A state of size `t` can occur only after the final one of `t` queries and
is therefore never queried again.
-/
def cappedQueryState
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  project (fun _database => True) queryBound
    (queryState system queryBound
      (strictProject queryBound state))

/--
For a state known to contain at most `i < t` answers, the reachable capped query is exactly the
raw implemented compressed-oracle query.  Neither projection discards amplitude.
-/
theorem capped_query_state_eq_query_state_of_bounded_lt
    (system : PhaseSystem Output Phase)
    (queryBound bound : Nat)
    (state : State Input Output Phase Workspace)
    (belowCap : bound < queryBound)
    (bounded : BoundedState bound state) :
    cappedQueryState system queryBound state =
      queryState system queryBound state := by
  unfold cappedQueryState
  rw [strict_project_eq_of_bounded_lt bounded belowCap]
  have oneStepBounded :
      BoundedState (bound + 1) (queryState system queryBound state) :=
    query_state_bounded_succ_of_bounded
      system queryBound bound state belowCap bounded
  have capBounded :
      BoundedState queryBound (queryState system queryBound state) :=
    bounded_state_mono (Nat.succ_le_iff.mpr belowCap) oneStepBounded
  exact capBounded

theorem capped_query_state_bounded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    BoundedState queryBound (cappedQueryState system queryBound state) := by
  unfold BoundedState cappedQueryState
  exact project_project (fun _database => True) queryBound _

/--
An arbitrary adversary computation between oracle calls.  Commuting with every database
projection is the exact statement that the step acts on adversary registers and leaves the
compressed database register untouched.
-/
structure DatabaseBlindContraction where
  apply : State Input Output Phase Workspace ->
    State Input Output Phase Workspace
  mapAdd : ∀ left right, apply (left + right) = apply left + apply right
  contractive : ∀ state, stateNorm (apply state) <= stateNorm state
  commutesProject :
    ∀ (property : Database Input Output -> Prop)
      [DecidablePred property] queryBound state,
      project property queryBound (apply state) =
        apply (project property queryBound state)

namespace DatabaseBlindContraction

theorem preserves_bounded
    (step : DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    {queryBound : Nat}
    {state : State Input Output Phase Workspace}
    (bounded : BoundedState queryBound state) :
    BoundedState queryBound (step.apply state) := by
  unfold BoundedState at bounded ⊢
  rw [step.commutesProject]
  rw [bounded]

end DatabaseBlindContraction

/-- One capped compressed-oracle query followed by one database-blind adversary step. -/
def evolve
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (step : DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  step.apply (cappedQueryState system queryBound state)

/-- One unprojected compressed-oracle query followed by one database-blind adversary step. -/
def rawEvolve
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (step : DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state : State Input Output Phase Workspace) :
    State Input Output Phase Workspace :=
  step.apply (queryState system queryBound state)

/-- Execute a finite sequence of compressed-oracle queries and inter-query computations. -/
def run
    (system : PhaseSystem Output Phase)
    (queryBound : Nat) :
    List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) ->
      State Input Output Phase Workspace ->
        State Input Output Phase Workspace
  | [], state => state
  | step :: remaining, state =>
      run system queryBound remaining
        (evolve system queryBound step state)

/-- Execute the same finite sequence without inserting support projections. -/
def rawRun
    (system : PhaseSystem Output Phase)
    (queryBound : Nat) :
    List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)) ->
      State Input Output Phase Workspace ->
        State Input Output Phase Workspace
  | [], state => state
  | step :: remaining, state =>
      rawRun system queryBound remaining
        (rawEvolve system queryBound step state)

/--
The projected telescope execution is exactly the raw compressed-oracle execution whenever the
initial support bound plus the number of calls does not exceed the global query cap.
-/
theorem run_eq_raw_run_of_bounded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    )
    (state : State Input Output Phase Workspace)
    (initialBound : Nat)
    (capacity : initialBound + steps.length <= queryBound)
    (bounded : BoundedState initialBound state) :
    run system queryBound steps state =
      rawRun system queryBound steps state := by
  induction steps generalizing state initialBound with
  | nil =>
      rfl
  | cons step remaining inductionHypothesis =>
      have belowCap : initialBound < queryBound := by
        simp only [List.length_cons] at capacity
        omega
      have queryBounded :
          BoundedState (initialBound + 1)
            (queryState system queryBound state) :=
        query_state_bounded_succ_of_bounded
          system queryBound initialBound state belowCap bounded
      have evolvedBounded :
          BoundedState (initialBound + 1)
            (rawEvolve system queryBound step state) := by
        exact step.preserves_bounded queryBounded
      have remainingCapacity :
          (initialBound + 1) + remaining.length <= queryBound := by
        simp only [List.length_cons] at capacity
        omega
      rw [run, rawRun, evolve, rawEvolve,
        capped_query_state_eq_query_state_of_bounded_lt
          system queryBound initialBound state belowCap bounded]
      exact inductionHypothesis
        (state := step.apply (queryState system queryBound state))
        (initialBound := initialBound + 1)
        remainingCapacity evolvedBounded

theorem evolve_bounded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (step : DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state : State Input Output Phase Workspace) :
    BoundedState queryBound (evolve system queryBound step state) := by
  exact step.preserves_bounded
    (capped_query_state_bounded system queryBound state)

/-- A capped execution preserves the global database-size cap. -/
theorem run_bounded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    (bounded : BoundedState queryBound state) :
    BoundedState queryBound
      (run system queryBound steps state) := by
  induction steps generalizing state with
  | nil =>
      exact bounded
  | cons step remaining inductionHypothesis =>
      rw [run]
      exact inductionHypothesis
        (state := evolve system queryBound step state)
        (evolve_bounded system queryBound step state)

/--
The raw execution has the same support cap when it starts from bounded support and stays within
the configured query capacity.
-/
theorem raw_run_bounded_of_bounded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    (initialBound : Nat)
    (capacity : initialBound + steps.length <= queryBound)
    (bounded : BoundedState initialBound state) :
    BoundedState queryBound
      (rawRun system queryBound steps state) := by
  have initialWithinCap : initialBound <= queryBound := by
    omega
  rw [← run_eq_raw_run_of_bounded
    system queryBound steps state initialBound capacity bounded]
  exact run_bounded system queryBound steps state
    (bounded_state_mono initialWithinCap bounded)

/-- The implemented reachable capped query is contractive. -/
theorem capped_query_state_contractive
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) :
    stateNorm (cappedQueryState system queryBound state) <= stateNorm state := by
  apply le_trans (state_norm_le_of_norm_squared_le
    (project_norm_squared_le (fun _database => True) queryBound
      (queryState system queryBound
        (strictProject queryBound state))))
  apply le_trans (state_norm_le_of_norm_squared_le
    (query_state_contractive_of_strict_support system queryBound
      (strictProject queryBound state)
      (strict_project_strict_support queryBound state)))
  exact state_norm_le_of_norm_squared_le
    (strict_project_norm_squared_le queryBound state)

theorem evolve_subnormalized
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (step : DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    {state : State Input Output Phase Workspace}
    (subnormalized : Subnormalized state) :
    Subnormalized (evolve system queryBound step state) := by
  unfold Subnormalized at subnormalized ⊢
  have evolveContraction :
      stateNorm (evolve system queryBound step state) <= stateNorm state :=
    step.contractive _ |>.trans
      (capped_query_state_contractive system queryBound state)
  have stateSquared : stateNorm state ^ 2 <= 1 := by
    rw [state_norm_sq_eq_norm_squared]
    exact subnormalized
  have evolvedSquared :
      stateNorm (evolve system queryBound step state) ^ 2 <= 1 := by
    nlinarith [state_norm_nonnegative
      (evolve system queryBound step state), state_norm_nonnegative state]
  rw [← state_norm_sq_eq_norm_squared]
  exact evolvedSquared

/-- A capped query sequence preserves subnormalization. -/
theorem run_subnormalized
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    (subnormalized : Subnormalized state) :
    Subnormalized (run system queryBound steps state) := by
  induction steps generalizing state with
  | nil =>
      exact subnormalized
  | cons step remaining inductionHypothesis =>
      rw [run]
      exact inductionHypothesis
        (state := evolve system queryBound step state)
        (evolve_subnormalized system queryBound step subnormalized)

/--
The exact raw execution preserves subnormalization whenever its support remains within the query
capacity.
-/
theorem raw_run_subnormalized_of_bounded
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    (initialBound : Nat)
    (capacity : initialBound + steps.length <= queryBound)
    (bounded : BoundedState initialBound state)
    (subnormalized : Subnormalized state) :
    Subnormalized (rawRun system queryBound steps state) := by
  rw [← run_eq_raw_run_of_bounded
    system queryBound steps state initialBound capacity bounded]
  exact run_subnormalized system queryBound steps state subnormalized

/--
One query can increase the property amplitude by at most the square root of the exact local
operator loss.
-/
theorem one_query_property_amplitude
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (step : DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace))
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (subnormalized : Subnormalized state) :
    stateNorm
        (project property queryBound
          (evolve system queryBound step state)) <=
      stateNorm (project property queryBound state) +
        Real.sqrt (6 * bound) := by
  have decomposition :
      project property queryBound (strictProject queryBound state) +
          project (complement property) queryBound
            (strictProject queryBound state) =
        strictProject queryBound state := by
    rw [project_add_complement_eq_bounded_project]
    exact strict_project_bounded queryBound state
  have queryDecomposition :
      queryState system queryBound (strictProject queryBound state) =
        queryState system queryBound
            (project property queryBound
              (strictProject queryBound state)) +
          queryState system queryBound
            (project (complement property) queryBound
              (strictProject queryBound state)) := by
    calc
      queryState system queryBound (strictProject queryBound state) =
          queryState system queryBound
            (project property queryBound (strictProject queryBound state) +
              project (complement property) queryBound
                (strictProject queryBound state)) :=
        congrArg (queryState system queryBound) decomposition.symm
      _ =
          queryState system queryBound
              (project property queryBound
                (strictProject queryBound state)) +
            queryState system queryBound
              (project (complement property) queryBound
                (strictProject queryBound state)) := by
        change
          queryState system queryBound
              (fun basis =>
                project property queryBound (strictProject queryBound state) basis +
                  project (complement property) queryBound
                    (strictProject queryBound state) basis) =
            fun basis =>
              queryState system queryBound
                  (project property queryBound (strictProject queryBound state)) basis +
                queryState system queryBound
                  (project (complement property) queryBound
                    (strictProject queryBound state)) basis
        exact
          query_state_add system queryBound
            (project property queryBound (strictProject queryBound state))
            (project (complement property) queryBound
              (strictProject queryBound state))
  have projectedEvolution :
      project property queryBound
          (evolve system queryBound step state) =
        step.apply
            (project property queryBound
              (queryState system queryBound
                (project property queryBound
                  (strictProject queryBound state)))) +
          step.apply
            (projectedQueryState system property queryBound
              (strictProject queryBound state)) := by
    unfold evolve cappedQueryState projectedQueryState
    rw [step.commutesProject]
    rw [project_bounded_project]
    rw [queryDecomposition, project_add, step.mapAdd]
  rw [projectedEvolution]
  apply (state_norm_add_le _ _).trans
  have stablePart :
      stateNorm
          (step.apply
            (project property queryBound
              (queryState system queryBound
                (project property queryBound
                  (strictProject queryBound state))))) <=
        stateNorm (project property queryBound state) := by
    apply (step.contractive _ |>.trans ?_).trans
      (show
        stateNorm
            (project property queryBound
              (strictProject queryBound state)) <=
          stateNorm (project property queryBound state) by
        rw [project_strict_project]
        exact state_norm_le_of_norm_squared_le
          (strict_project_norm_squared_le queryBound
            (project property queryBound state)))
    apply state_norm_le_of_norm_squared_le
    apply (project_norm_squared_le property queryBound
      (queryState system queryBound
        (project property queryBound
          (strictProject queryBound state)))).trans
    exact query_state_contractive_of_strict_support
      system queryBound
      (project property queryBound (strictProject queryBound state))
      (project_preserves_strict_support property queryBound
        (strictProject queryBound state)
        (strict_project_strict_support queryBound state))
  have leakSquared :
      normSquared
          (projectedQueryState system property queryBound
            (strictProject queryBound state)) <=
        6 * bound := by
    exact norm_squared_projected_query_state_le_six_instability
      system property queryBound (strictProject queryBound state)
        instability (strict_project_subnormalized queryBound subnormalized)
  have leakPart :
      stateNorm
          (step.apply
            (projectedQueryState system property queryBound
              (strictProject queryBound state))) <=
        Real.sqrt (6 * bound) := by
    apply step.contractive _ |>.trans
    exact state_norm_le_sqrt _
      (mul_nonneg (by norm_num) instability.1.1) leakSquared
  exact add_le_add stablePart leakPart

/--
Exact finite-query telescoping theorem.  No asymptotic constant or hidden register factor occurs.
-/
theorem run_property_amplitude
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (subnormalized : Subnormalized state) :
    stateNorm
        (project property queryBound
          (run system queryBound steps state)) <=
      stateNorm (project property queryBound state) +
        (steps.length : ℝ) * Real.sqrt (6 * bound) := by
  induction steps generalizing state with
  | nil =>
      simp [run]
  | cons step remaining inductionHypothesis =>
      have evolvedSubnormalized :
          Subnormalized (evolve system queryBound step state) :=
        evolve_subnormalized system queryBound step subnormalized
      have tailBound :=
        inductionHypothesis
          (state := evolve system queryBound step state)
          evolvedSubnormalized
      have firstBound :=
        one_query_property_amplitude system property queryBound
          step state instability subnormalized
      rw [run]
      calc
        stateNorm
            (project property queryBound
              (run system queryBound remaining
                (evolve system queryBound step state))) <=
            stateNorm
                (project property queryBound
                  (evolve system queryBound step state)) +
              (remaining.length : ℝ) * Real.sqrt (6 * bound) :=
          tailBound
        _ <=
            (stateNorm (project property queryBound state) +
                Real.sqrt (6 * bound)) +
              (remaining.length : ℝ) * Real.sqrt (6 * bound) := by
          exact add_le_add firstBound (le_refl _)
        _ =
            stateNorm (project property queryBound state) +
              ((step :: remaining).length : ℝ) * Real.sqrt (6 * bound) := by
          rw [List.length_cons, Nat.cast_add, Nat.cast_one]
          ring

/--
CMS basic database lifting, in probability form, for a bounded normalized initial state with no
winning support.
-/
theorem database_game_probability_le
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (subnormalized : Subnormalized state)
    (initiallyOutside :
      project property queryBound state = 0) :
    normSquared
        (project property queryBound
          (run system queryBound steps state)) <=
      6 * (steps.length : ℝ) ^ 2 * bound := by
  have amplitudeBound :=
    run_property_amplitude system property queryBound
      steps state instability subnormalized
  rw [initiallyOutside, state_norm_zero, zero_add] at amplitudeBound
  have leftNonnegative :=
    state_norm_nonnegative
      (project property queryBound (run system queryBound steps state))
  have rightNonnegative :
      0 <= (steps.length : ℝ) * Real.sqrt (6 * bound) :=
    mul_nonneg (by positivity) (Real.sqrt_nonneg _)
  have squared :=
    mul_self_le_mul_self leftNonnegative amplitudeBound
  have boundNonnegative :
      0 <= 6 * bound :=
    mul_nonneg (by norm_num) instability.1.1
  have squaredPower :
      stateNorm
          (project property queryBound
            (run system queryBound steps state)) ^ 2 <=
        ((steps.length : ℝ) * Real.sqrt (6 * bound)) ^ 2 := by
    simpa [pow_two] using squared
  rw [state_norm_sq_eq_norm_squared] at squaredPower
  calc
    normSquared
        (project property queryBound
          (run system queryBound steps state)) <=
        ((steps.length : ℝ) * Real.sqrt (6 * bound)) ^ 2 :=
      squaredPower
    _ = 6 * (steps.length : ℝ) ^ 2 * bound := by
      rw [mul_pow, Real.sq_sqrt boundNonnegative]
      ring

/--
CMS database lifting for the raw implemented execution.  Starting from an empty-database support
and making at most `t` calls, the support projections used in the proof are exact identities.
-/
theorem raw_database_game_probability_le
    (system : PhaseSystem Output Phase)
    (property : Property Input Output)
    [DecidablePred property]
    (queryBound : Nat)
    (steps : List (DatabaseBlindContraction
      (Input := Input) (Output := Output) (Phase := Phase) (Workspace := Workspace)))
    (state : State Input Output Phase Workspace)
    {bound : ℝ}
    (instability : RealInstabilityBound property queryBound bound)
    (queryCapacity : steps.length <= queryBound)
    (emptyDatabaseSupport : BoundedState 0 state)
    (subnormalized : Subnormalized state)
    (initiallyOutside :
      project property queryBound state = 0) :
    normSquared
        (project property queryBound
          (rawRun system queryBound steps state)) <=
      6 * (steps.length : ℝ) ^ 2 * bound := by
  rw [← run_eq_raw_run_of_bounded
    system queryBound steps state 0 (by simpa using queryCapacity)
      emptyDatabaseSupport]
  exact database_game_probability_le
    system property queryBound steps state instability
      subnormalized initiallyOutside

end

end HegemonCrypto.CmsQuerySequence
