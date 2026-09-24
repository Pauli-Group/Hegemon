import HegemonCrypto.CCS
import Mathlib.Algebra.Field.ZMod

/-!
# Adversarial CCS examples

The examples use a one-row equation `x * y - 6 = 0` over `ZMod 17`. Each mutation changes one
semantic component and must be rejected by the executable checker.
-/

namespace HegemonCrypto.CCSExamples

open HegemonCrypto.CCS

local instance : Fact (Nat.Prime 17) := ⟨by decide⟩

abbrev ExampleField := ZMod 17

def selectorMatrix (selected : Fin 2) : Matrix (Fin 1) (Fin 2) ExampleField :=
  fun _ column => if column = selected then 1 else 0

def equationSystem
    (constant : ExampleField)
    (productFactors : Multiset (Fin 2)) : System ExampleField where
  rowCount := 1
  variableCount := 2
  matrixCount := 2
  termCount := 2
  matrix := selectorMatrix
  coefficient := fun term => if term = 0 then 1 else constant
  factors := fun term =>
    if term = 0 then productFactors else 0

def productSystem : System ExampleField :=
  equationSystem (-6) {0, 1}

def satisfyingAssignment : Fin 2 → ExampleField :=
  fun column => if column = 0 then 2 else 3

def changedWitnessAssignment : Fin 2 → ExampleField :=
  fun column => if column = 0 then 2 else 4

def changedCoefficientSystem : System ExampleField :=
  equationSystem (-5) {0, 1}

def omittedFactorSystem : System ExampleField :=
  equationSystem (-6) {0}

def duplicatedFactorSystem : System ExampleField :=
  equationSystem (-6) {0, 0, 1}

theorem product_system_accepts_exact_assignment :
    productSystem.satisfiesB satisfyingAssignment = true := by
  decide

theorem changed_coefficient_rejects :
    changedCoefficientSystem.satisfiesB satisfyingAssignment = false := by
  decide

theorem omitted_factor_rejects :
    omittedFactorSystem.satisfiesB satisfyingAssignment = false := by
  decide

theorem duplicated_factor_rejects :
    duplicatedFactorSystem.satisfiesB satisfyingAssignment = false := by
  decide

theorem changed_witness_rejects :
    productSystem.satisfiesB changedWitnessAssignment = false := by
  decide

end HegemonCrypto.CCSExamples
