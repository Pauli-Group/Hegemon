import HegemonCrypto.FiniteOracleDatabase
import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Algebra.BigOperators.Option
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Data.Fintype.OfMap
import Mathlib.Data.Fintype.Option
import Mathlib.Data.Fintype.Pi
import Mathlib.Data.Fintype.Prod
import Mathlib.Data.Real.Basic

/-!
# Canonical one-input database fibers

At one fixed oracle input, every finite recorded database is uniquely an absent base database plus
either no recorded output or one recorded output.  This equivalence is the reindexing used by the
CMS local-operator proof; it prevents hidden duplicate or missing database amplitudes.
-/

namespace HegemonCrypto.DatabaseFiber

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase

noncomputable section

variable {Input Output : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output]

/-- Databases absent at one selected input. -/
abbrev AbsentDatabase (input : Input) :=
  { database : Database Input Output // database input = none }

/-- Canonical absent-base and optional-output coordinate. -/
abbrev Coordinate (input : Input) :=
  AbsentDatabase (Output := Output) input × Option Output

/-- Every database has one canonical coordinate at the selected input. -/
def databaseEquiv (input : Input) :
    Database Input Output ≃ Coordinate (Output := Output) input where
  toFun database :=
    (⟨erase database input, erase_same database input⟩, database input)
  invFun coordinate :=
    match coordinate.2 with
    | none => coordinate.1.1
    | some output => insert coordinate.1.1 input output
  left_inv database := by
    cases recorded : database input with
    | none =>
        simpa [recorded] using erase_of_absent database input recorded
    | some output =>
        simpa [recorded] using
          erase_then_insert_restores database input output recorded
  right_inv coordinate := by
    rcases coordinate with ⟨⟨base, absent⟩, outputOption⟩
    cases outputOption with
    | none =>
        apply Prod.ext
        · apply Subtype.ext
          exact erase_of_absent base input absent
        · exact absent
    | some output =>
        apply Prod.ext
        · apply Subtype.ext
          exact insert_then_erase_restores_of_absent base input output absent
        · simp

omit [Fintype Input] [Fintype Output] [DecidableEq Output] in
/-- The absent coordinate maps back to its base database. -/
theorem databaseEquiv_symm_none
    (input : Input)
    (base : AbsentDatabase (Output := Output) input) :
    (databaseEquiv (Output := Output) input).symm (base, none) = base.1 := by
  rfl

omit [Fintype Input] [Fintype Output] [DecidableEq Output] in
/-- A recorded coordinate maps back by inserting its output. -/
theorem databaseEquiv_symm_some
    (input : Input)
    (base : AbsentDatabase (Output := Output) input)
    (output : Output) :
    (databaseEquiv (Output := Output) input).symm (base, some output) =
      insert base.1 input output := by
  rfl

omit [DecidableEq Output] in
/-- Reindex a finite sum over all databases into canonical fibers. -/
theorem sum_database_eq_sum_fibers
    {Value : Type*}
    [AddCommMonoid Value]
    (input : Input)
    (value : Database Input Output -> Value) :
    (∑ database : Database Input Output, value database) =
      ∑ base : AbsentDatabase (Output := Output) input,
        (value base.1 +
          ∑ output : Output, value (insert base.1 input output)) := by
  rw [← (databaseEquiv (Output := Output) input).symm.sum_comp value]
  rw [Fintype.sum_prod_type]
  simp [Coordinate, databaseEquiv]

end

end HegemonCrypto.DatabaseFiber
