import HegemonCrypto.CCS
import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Tactic.Ring

/-!
# Quadratic arithmetic programs

This module defines a compact affine-quadratic language and a canonical compilation into CCS.
It is deliberately independent of SmallWood: the production adapter only needs to generate this
language and prove that its rows represent the production sparse tables and expression DAG.
-/

namespace HegemonCrypto.QuadraticProgram

open scoped BigOperators

universe u

variable {F : Type u} [CommRing F]

/-- An affine form `constant + sum coefficient[i] * assignment[i]`. -/
structure AffineForm (F : Type u) [CommRing F] (variableCount : Nat) where
  constant : F
  coefficient : Fin variableCount → F

def AffineForm.eval
    {variableCount : Nat}
    (form : AffineForm F variableCount)
    (assignment : Fin variableCount → F) : F :=
  form.constant + ∑ index, form.coefficient index * assignment index

/-- One equation `left * right + linear = 0`. -/
structure Equation (F : Type u) [CommRing F] (variableCount : Nat) where
  left : AffineForm F variableCount
  right : AffineForm F variableCount
  linear : AffineForm F variableCount

def Equation.Satisfied
    {variableCount : Nat}
    (equation : Equation F variableCount)
    (assignment : Fin variableCount → F) : Prop :=
  equation.left.eval assignment * equation.right.eval assignment +
      equation.linear.eval assignment = 0

/-- A finite indexed collection of affine-quadratic equations. -/
structure Program (F : Type u) [CommRing F] where
  variableCount : Nat
  rowCount : Nat
  equation : Fin rowCount → Equation F variableCount

def Program.Satisfies
    (program : Program F)
    (assignment : Fin program.variableCount → F) : Prop :=
  ∀ row, (program.equation row).Satisfied assignment

/-- Add a leading constant-one coordinate to a program assignment. -/
def augmentAssignment
    {variableCount : Nat}
    (assignment : Fin variableCount → F) : Fin (variableCount + 1) → F :=
  Fin.cases 1 assignment

private def oneMatrix (program : Program F) :
    Matrix (Fin (program.rowCount + 1)) (Fin (program.variableCount + 1)) F :=
  fun _ column => Fin.cases 1 (fun _ => 0) column

private def affineMatrix
    (program : Program F)
    (select : Equation F program.variableCount → AffineForm F program.variableCount) :
    Matrix (Fin (program.rowCount + 1)) (Fin (program.variableCount + 1)) F :=
  fun row column =>
    Fin.cases 0
      (fun equationRow =>
        Fin.cases
          (select (program.equation equationRow)).constant
          (select (program.equation equationRow)).coefficient
          column)
      row

private def matrices (program : Program F) :
    List (Matrix (Fin (program.rowCount + 1)) (Fin (program.variableCount + 1)) F) :=
  [ oneMatrix program,
    affineMatrix program Equation.linear,
    affineMatrix program Equation.left,
    affineMatrix program Equation.right ]

private def termCoefficients : List F := [-1, 1, 1, 1]

private def termFactors : List (Multiset (Fin 4)) :=
  [ 0, {(0 : Fin 4)}, {(1 : Fin 4)}, {(2 : Fin 4), (3 : Fin 4)} ]

/-- Canonical CCS compilation. Row zero forces the augmented coordinate to equal one. -/
def compile (program : Program F) : HegemonCrypto.CCS.System F where
  rowCount := program.rowCount + 1
  variableCount := program.variableCount + 1
  matrixCount := 4
  termCount := 4
  matrix := matrices program |>.get
  coefficient := termCoefficients.get
  factors := termFactors.get

/-- Remove the leading constant coordinate from a compiled assignment. -/
def tailAssignment
    {variableCount : Nat}
    (assignment : Fin (variableCount + 1) → F) : Fin variableCount → F :=
  fun index => assignment index.succ

private def firstRow (program : Program F) : Fin (compile program).rowCount :=
  ⟨0, by simp [compile]⟩

private theorem oneMatrix_value
    (program : Program F)
    (assignment : Fin (program.variableCount + 1) → F)
    (row : Fin (program.rowCount + 1)) :
    ∑ column, oneMatrix program row column * assignment column = assignment 0 := by
  simp [oneMatrix, Fin.sum_univ_succ]

private theorem affineMatrix_value_zero
    (program : Program F)
    (select : Equation F program.variableCount → AffineForm F program.variableCount)
    (assignment : Fin (program.variableCount + 1) → F) :
    ∑ column, affineMatrix program select 0 column * assignment column = 0 := by
  simp [affineMatrix]

private theorem affineMatrix_value_succ
    (program : Program F)
    (select : Equation F program.variableCount → AffineForm F program.variableCount)
    (assignment : Fin (program.variableCount + 1) → F)
    (row : Fin program.rowCount) :
    ∑ column, affineMatrix program select row.succ column * assignment column =
      (select (program.equation row)).constant * assignment 0 +
        ∑ index,
          (select (program.equation row)).coefficient index *
            tailAssignment assignment index := by
  simp [affineMatrix, tailAssignment, Fin.sum_univ_succ]

theorem compile_rowValue_zero
    (program : Program F)
    (assignment : Fin (program.variableCount + 1) → F) :
    (compile program).rowValue assignment (firstRow program) = -1 + assignment 0 := by
  change
    (∑ term : Fin 4,
      (compile program).coefficient term *
        (compile program).termValue assignment (firstRow program) term) =
      -1 + assignment 0
  rw [Fin.sum_univ_four]
  simp [HegemonCrypto.CCS.System.termValue,
    HegemonCrypto.CCS.System.matrixValue, compile, matrices, termCoefficients,
    termFactors, firstRow]
  change
    -1 +
          (∑ index : Fin (program.variableCount + 1),
            oneMatrix program 0 index * assignment index) +
        (∑ index : Fin (program.variableCount + 1),
          affineMatrix program Equation.linear 0 index * assignment index) +
      (∑ index : Fin (program.variableCount + 1),
          affineMatrix program Equation.left 0 index * assignment index) *
        (∑ index : Fin (program.variableCount + 1),
          affineMatrix program Equation.right 0 index * assignment index) =
      -1 + assignment 0
  rw [oneMatrix_value program assignment (0 : Fin (program.rowCount + 1))]
  rw [affineMatrix_value_zero program Equation.linear assignment]
  rw [affineMatrix_value_zero program Equation.left assignment]
  rw [affineMatrix_value_zero program Equation.right assignment]
  ring

theorem compile_rowValue_succ
    (program : Program F)
    (assignment : Fin (program.variableCount + 1) → F)
    (hone : assignment 0 = 1)
    (row : Fin program.rowCount) :
    (compile program).rowValue assignment row.succ =
      (program.equation row).left.eval (tailAssignment assignment) *
          (program.equation row).right.eval (tailAssignment assignment) +
        (program.equation row).linear.eval (tailAssignment assignment) := by
  change
    (∑ term : Fin 4,
      (compile program).coefficient term *
        (compile program).termValue assignment row.succ term) = _
  rw [Fin.sum_univ_four]
  simp [HegemonCrypto.CCS.System.termValue,
    HegemonCrypto.CCS.System.matrixValue, compile, matrices, termCoefficients,
    termFactors]
  change
    -1 +
          (∑ index : Fin (program.variableCount + 1),
            oneMatrix program row.succ index * assignment index) +
        (∑ index : Fin (program.variableCount + 1),
          affineMatrix program Equation.linear row.succ index * assignment index) +
      (∑ index : Fin (program.variableCount + 1),
          affineMatrix program Equation.left row.succ index * assignment index) *
        (∑ index : Fin (program.variableCount + 1),
          affineMatrix program Equation.right row.succ index * assignment index) = _
  rw [oneMatrix_value program assignment row.succ]
  rw [affineMatrix_value_succ program Equation.linear assignment row]
  rw [affineMatrix_value_succ program Equation.left assignment row]
  rw [affineMatrix_value_succ program Equation.right assignment row]
  simp [AffineForm.eval, hone]
  ring

theorem assignment_eq_augment_tail
    {variableCount : Nat}
    (assignment : Fin (variableCount + 1) → F)
    (hone : assignment 0 = 1) :
    assignment = augmentAssignment (tailAssignment assignment) := by
  funext index
  refine Fin.cases ?_ (fun _ => rfl) index
  simpa [augmentAssignment] using hone

@[simp] theorem tailAssignment_augmentAssignment
    {variableCount : Nat}
    (assignment : Fin variableCount → F) :
    tailAssignment (augmentAssignment assignment) = assignment := by
  funext index
  rfl

theorem compile_satisfies_iff
    (program : Program F)
    (assignment : Fin (program.variableCount + 1) → F) :
    (compile program).Satisfies assignment ↔
      assignment 0 = 1 ∧ program.Satisfies (tailAssignment assignment) := by
  constructor
  · intro hsatisfies
    have hzero := hsatisfies (firstRow program)
    have hone : assignment 0 = 1 := by
      have hsub : assignment 0 - 1 = 0 := by
        simpa [HegemonCrypto.CCS.System.RowSatisfied, compile_rowValue_zero,
          sub_eq_add_neg, add_comm] using hzero
      exact sub_eq_zero.mp hsub
    refine ⟨hone, ?_⟩
    intro row
    have hrow := hsatisfies row.succ
    simpa [HegemonCrypto.CCS.System.RowSatisfied, Equation.Satisfied,
      compile_rowValue_succ program assignment hone row] using hrow
  · rintro ⟨hone, hprogram⟩ row
    change Fin (program.rowCount + 1) at row
    refine Fin.cases ?_ (fun equationRow => ?_) row
    · change (compile program).rowValue assignment (firstRow program) = 0
      simp [compile_rowValue_zero, hone]
    · have hrow := hprogram equationRow
      simpa [HegemonCrypto.CCS.System.RowSatisfied, Equation.Satisfied,
        compile_rowValue_succ program assignment hone equationRow] using hrow

theorem compile_complete_iff
    (program : Program F)
    (assignment : Fin program.variableCount → F) :
    (compile program).Satisfies (augmentAssignment assignment) ↔
      program.Satisfies assignment := by
  rw [compile_satisfies_iff]
  simp [augmentAssignment]

end HegemonCrypto.QuadraticProgram
