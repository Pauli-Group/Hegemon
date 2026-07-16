import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import Mathlib.Data.Matrix.Basic
import Mathlib.Data.Multiset.Basic

/-!
# Customizable constraint systems

This module follows the conventional CCS equation directly. Repeated matrix factors are
represented by a `Multiset`, rather than being collapsed into a set.
-/

namespace HegemonCrypto.CCS

open scoped BigOperators

universe u

/-- A finite customizable constraint system over a field. -/
structure System (F : Type u) [Field F] where
  rowCount : Nat
  variableCount : Nat
  matrixCount : Nat
  termCount : Nat
  matrix : Fin matrixCount → Matrix (Fin rowCount) (Fin variableCount) F
  coefficient : Fin termCount → F
  factors : Fin termCount → Multiset (Fin matrixCount)

variable {F : Type u} [Field F]

/-- The value of one matrix-vector product at one CCS row. -/
def System.matrixValue
    (system : System F)
    (assignment : Fin system.variableCount → F)
    (matrixIndex : Fin system.matrixCount)
    (row : Fin system.rowCount) : F :=
  ∑ column, system.matrix matrixIndex row column * assignment column

/-- The product selected by one CCS term. An empty factor multiset denotes the constant one. -/
def System.termValue
    (system : System F)
    (assignment : Fin system.variableCount → F)
    (row : Fin system.rowCount)
    (term : Fin system.termCount) : F :=
  (system.factors term).map
    (fun matrixIndex => system.matrixValue assignment matrixIndex row) |>.prod

/-- The left-hand side of the canonical CCS equation at one row. -/
def System.rowValue
    (system : System F)
    (assignment : Fin system.variableCount → F)
    (row : Fin system.rowCount) : F :=
  ∑ term, system.coefficient term * system.termValue assignment row term

/-- Proposition-valued satisfaction of one CCS row. -/
def System.RowSatisfied
    (system : System F)
    (assignment : Fin system.variableCount → F)
    (row : Fin system.rowCount) : Prop :=
  system.rowValue assignment row = 0

/-- Proposition-valued satisfaction of every row in a CCS instance. -/
def System.Satisfies
    (system : System F)
    (assignment : Fin system.variableCount → F) : Prop :=
  ∀ row, system.RowSatisfied assignment row

/-- Independently executable equality check for one row. -/
def System.rowSatisfiedB
    [DecidableEq F]
    (system : System F)
    (assignment : Fin system.variableCount → F)
    (row : Fin system.rowCount) : Bool :=
  decide (system.rowValue assignment row = 0)

/-- Independently executable finite traversal of all CCS rows. -/
def System.satisfiesB
    [DecidableEq F]
    (system : System F)
    (assignment : Fin system.variableCount → F) : Bool :=
  (List.finRange system.rowCount).all (system.rowSatisfiedB assignment)

theorem System.rowSatisfiedB_iff
    [DecidableEq F]
    (system : System F)
    (assignment : Fin system.variableCount → F)
    (row : Fin system.rowCount) :
    system.rowSatisfiedB assignment row = true ↔
      system.RowSatisfied assignment row := by
  simp [System.rowSatisfiedB, System.RowSatisfied]

theorem System.satisfiesB_iff
    [DecidableEq F]
    (system : System F)
    (assignment : Fin system.variableCount → F) :
    system.satisfiesB assignment = true ↔ system.Satisfies assignment := by
  simp [System.satisfiesB, System.Satisfies, System.rowSatisfiedB,
    System.RowSatisfied]

end HegemonCrypto.CCS
