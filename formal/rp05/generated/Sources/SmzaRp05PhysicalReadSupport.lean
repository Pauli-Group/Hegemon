import SmzaRp05PhysicalTerminalRead
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle

/-! Coordinate-local support growth for the physical terminal read.
This module precedes the charged-read implementation in the import DAG. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PhysicalReadSupport

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.SmallWood.V8Smz9CoherentVectorMerkle
open HegemonCrypto.SmallWood.SmzaRp05PhysicalTerminalRead

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000

variable {Key Counter Work : Type}
variable [Fintype Key] [DecidableEq Key]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype Work] [DecidableEq Work]

theorem coordinate_projection_decompress_at_of_ne
    (selected : Key) (answer : VectorOutput Counter) (changed : Key)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (different : selected ≠ changed) :
    coordinateEventProjection selected answer (decompressAt changed state) =
      decompressAt changed
        (coordinateEventProjection selected answer state) := by
  funext target
  rw [decompress_at_eq_sum_kernel]
  unfold coordinateEventProjection
  by_cases accepted : target.database selected = some answer
  · rw [if_pos accepted, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro source _
    have sourceAccepted :
        setDatabaseCoordinate target.database changed source selected =
          some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_pos sourceAccepted]
  · rw [if_neg accepted]
    symm
    apply Finset.sum_eq_zero
    intro source _
    have sourceRejected :
        setDatabaseCoordinate target.database changed source selected ≠
          some answer := by
      rw [set_database_coordinate_other target.database different source]
      exact accepted
    rw [if_neg sourceRejected]
    simp

theorem coordinate_projection_decompress_list_of_outside
    (selected : Key) (answer : VectorOutput Counter)
    (inputs : List Key)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (outside : ∀ changed ∈ inputs, selected ≠ changed) :
    coordinateEventProjection selected answer (decompressList inputs state) =
      decompressList inputs
        (coordinateEventProjection selected answer state) := by
  induction inputs with
  | nil => rfl
  | cons changed remaining ih =>
      have changedOutside : selected ≠ changed := outside changed (by simp)
      have remainingOutside : ∀ input ∈ remaining, selected ≠ input := by
        intro input member
        exact outside input (by simp [member])
      simp only [decompress_list_cons]
      rw [coordinate_projection_decompress_at_of_ne
        selected answer changed _ changedOutside]
      rw [ih remainingOutside]

theorem coordinate_projection_decompress_except
    (selected : Key) (answer : VectorOutput Counter)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work) :
    coordinateEventProjection selected answer
        (decompressExcept selected state) =
      decompressExcept selected
        (coordinateEventProjection selected answer state) := by
  unfold decompressExcept
  apply coordinate_projection_decompress_list_of_outside
  intro changed member
  have erased : changed ∈ (Finset.univ : Finset Key).erase selected := by
    simpa using member
  exact fun same => (Finset.mem_erase.mp erased).1 same.symm

/-- The selected physical read is local to one CMS database coordinate;
all other decompression reflections cancel. -/
theorem physical_read_branch_eq_selected
    (selected : Key) (answer : VectorOutput Counter)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work) :
    physicalReadBranch selected answer state =
      decompressAt selected
        (coordinateEventProjection selected answer
          (decompressAt selected state)) := by
  unfold physicalReadBranch
  rw [global_decompress_eq_selected_last,
    global_decompress_eq_selected_last]
  rw [coordinate_projection_decompress_except]
  unfold decompressExcept
  rw [decompress_at_decompress_list_commutes]
  rw [decompress_list_involutive]

/-- One vector read can add at most one compressed-database cell.  The proof
is purely fiber-local and works for the entire VectorOutput Counter group. -/
theorem selected_physical_read_branch_bounded_succ
    (selected : Key) (answer : VectorOutput Counter)
    (bound : Nat)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1)
      (decompressAt selected
        (coordinateEventProjection selected answer
          (decompressAt selected state))) := by
  unfold BoundedState
  funext target
  by_cases within : size target.database ≤ bound + 1
  · simp [project, within]
  · have above : bound + 1 < size target.database :=
      Nat.lt_of_not_ge within
    let coordinate :=
      databaseEquiv (Output := VectorOutput Counter) selected target.database
    have databaseEq :
        (databaseEquiv (Output := VectorOutput Counter) selected).symm
          coordinate = target.database := by
      exact Equiv.symm_apply_apply
        (databaseEquiv (Output := VectorOutput Counter) selected)
        target.database
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
          (coordinateEventProjection selected answer
            (decompressAt selected state))
          target.input target.phase target.workspace selected base = 0 := by
      ext source
      rw [database_fiber_state_apply]
      by_cases recorded :
          ((databaseEquiv (Output := VectorOutput Counter) selected).symm
            (base, source)) selected = some answer
      · simp only [coordinateEventProjection, recorded, if_true]
        simpa only [database_fiber_state_apply] using
          congrArg (fun fiber => fiber source) decompressedFiberZero
      · simp [coordinateEventProjection, recorded]
    have targetEq :
        ({ input := target.input
           phase := target.phase
           workspace := target.workspace
           database :=
             (databaseEquiv (Output := VectorOutput Counter) selected).symm
               (base, targetCoordinate) } :
          Basis Key (VectorOutput Counter)
            (VectorOutput Counter) Work) = target := by
      cases target
      simp_all
    have targetZero :
        decompressAt selected
          (coordinateEventProjection selected answer
            (decompressAt selected state)) target = 0 := by
      rw [← targetEq, decompress_at_apply_coordinate, projectedFiberZero]
      simp
    simp [project, within, targetZero]

theorem physical_read_branch_bounded_succ
    (selected : Key) (answer : VectorOutput Counter)
    (bound : Nat)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) Work)
    (bounded : BoundedState bound state) :
    BoundedState (bound + 1) (physicalReadBranch selected answer state) := by
  rw [physical_read_branch_eq_selected]
  exact selected_physical_read_branch_bounded_succ
    selected answer bound state bounded

end
end HegemonCrypto.SmallWood.SmzaRp05PhysicalReadSupport
