import HegemonCrypto.QuadraticProgram
import Mathlib.Algebra.Field.ZMod

/-!
# Quadratic-program compiler mutation examples

The one-variable program is `x * x - 4 = 0` over `ZMod 17`. The examples exercise the
canonical compiler and make the row-omission failure mode executable and explicit.
-/

namespace HegemonCrypto.QuadraticProgramExamples

open HegemonCrypto.CCS
open HegemonCrypto.QuadraticProgram

local instance : Fact (Nat.Prime 17) := ⟨by decide⟩

abbrev ExampleField := ZMod 17

def selectedVariable : AffineForm ExampleField 1 where
  constant := 0
  coefficient := fun _ => 1

def negativeFour : AffineForm ExampleField 1 where
  constant := -4
  coefficient := fun _ => 0

def squareEquation : Equation ExampleField 1 where
  left := selectedVariable
  right := selectedVariable
  linear := negativeFour

def squareProgram : Program ExampleField where
  variableCount := 1
  rowCount := 1
  equation := fun _ => squareEquation

def omittedEquationProgram : Program ExampleField where
  variableCount := 1
  rowCount := 0
  equation := fun row => Fin.elim0 row

def duplicatedEquationProgram : Program ExampleField where
  variableCount := 1
  rowCount := 2
  equation := fun _ => squareEquation

def changedConstantProgram : Program ExampleField where
  variableCount := 1
  rowCount := 1
  equation := fun _ =>
    { squareEquation with linear := { negativeFour with constant := -5 } }

def satisfyingAssignment : Fin 1 → ExampleField := fun _ => 2

def invalidAssignment : Fin 1 → ExampleField := fun _ => 3

theorem canonical_compiler_accepts_valid_assignment :
    (compile squareProgram).satisfiesB (augmentAssignment satisfyingAssignment) = true := by
  decide

theorem canonical_compiler_rejects_invalid_assignment :
    (compile squareProgram).satisfiesB (augmentAssignment invalidAssignment) = false := by
  decide

theorem omitted_equation_mutation_would_accept_invalid_assignment :
    (compile omittedEquationProgram).satisfiesB (augmentAssignment invalidAssignment) = true := by
  decide

theorem duplicated_equation_does_not_create_a_bypass :
    (compile duplicatedEquationProgram).satisfiesB (augmentAssignment invalidAssignment) = false := by
  decide

theorem changed_constant_rejects_previously_valid_assignment :
    (compile changedConstantProgram).satisfiesB (augmentAssignment satisfyingAssignment) = false := by
  decide

end HegemonCrypto.QuadraticProgramExamples
