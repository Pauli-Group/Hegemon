import HegemonCrypto.NativePrivateSpendQ58Parameters

/-! Current COMPFF01 geometry only. Historical Q58 results keep their old types.
These arithmetic facts do not discharge response-universal bad-matrix counting.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGeometry
open scoped BigOperators
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def rows : Nat := 26210
def linearChecks : Nat := 1344594
def nonlinearBatches : Nat := 5210
def unstackedColumns : Nat := rows + 20
def headColumns : Nat := (unstackedColumns + 1) / 2
def decodedCoordinates : Nat := 58 + headColumns
def degree : Nat := decodedCoordinates - 1
def domain : Nat := 8388608
def threshold : Nat := 360448
def multiplicity : Nat := 6
def xBound : Nat := 2162688
def yBound : Nat := 165
def zBound : Nat := 10000

def variableCount : Nat :=
  ∑ j ∈ Finset.range yBound, (xBound - degree * j) * (zBound - j)

def equationCount : Nat :=
  domain * ((multiplicity * (multiplicity + 1) / 2) * zBound -
    (multiplicity ^ 3 - multiplicity) / 6)

def labelBudget : Nat :=
  zBound + 2 * yBound * zBound +
  2 * (1 + (2 * degree - 1) * yBound) * yBound * zBound +
  (domain * ((4 * degree - 2) * yBound * zBound + yBound) +
    (threshold - degree - 1)) / (threshold - degree) + domain * yBound

theorem exact_geometry :
    unstackedColumns = 26230 ∧ headColumns = 13115 ∧
    decodedCoordinates = 13173 ∧ degree = 13172 := by
  norm_num [unstackedColumns, headColumns, decodedCoordinates, degree, rows]

theorem exact_analysis_geometry :
    xBound = multiplicity * threshold ∧
    degree * (yBound - 1) < xBound ∧ xBound ≤ degree * yBound ∧
    degree < threshold ∧ threshold < domain := by
  norm_num [xBound, multiplicity, threshold, degree, decodedCoordinates,
    headColumns, unstackedColumns, rows, yBound, domain]

theorem exact_equation_count : equationCount = 1761314078720 := by
  norm_num [equationCount, domain, multiplicity, zBound]

theorem exact_variable_count : variableCount = 1776546913240 := by
  have hc : (variableCount : ℚ) = 1776546913240 := by
    simp only [variableCount, Nat.cast_sum, Nat.cast_mul]
    calc
      _ = ∑ j ∈ Finset.range yBound,
          (2162688 - 13172 * (j : ℚ)) * (10000 - (j : ℚ)) := by
        apply Finset.sum_congr rfl
        intro j hj
        have hjlt : j < yBound := by simpa using hj
        have hx : degree * j ≤ xBound := by
          norm_num [degree, decodedCoordinates, headColumns, unstackedColumns,
            rows, xBound, yBound] at hjlt ⊢
          omega
        have hz : j ≤ zBound := by
          norm_num [zBound, yBound] at hjlt ⊢
          omega
        rw [Nat.cast_sub hx, Nat.cast_sub hz]
        norm_num [degree, decodedCoordinates, headColumns, unstackedColumns,
          rows, xBound, zBound]
      _ = _ := by
        rw [NativePrivateSpendQ58Parameters.sum_affine_product]
        norm_num [yBound]
  exact_mod_cast hc

theorem variable_count_strict_surplus : equationCount < variableCount := by
  rw [exact_equation_count, exact_variable_count]
  norm_num

theorem exact_label_budget : labelBudget = 16445033384594 := by
  norm_num [labelBudget, degree, decodedCoordinates, headColumns,
    unstackedColumns, rows, domain, threshold, yBound, zBound]

end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentGeometry
