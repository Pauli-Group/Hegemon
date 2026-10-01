import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Ring
import Mathlib.Tactic.Push
import Mathlib.Algebra.BigOperators.Fin

/-! A stronger, unweighted counting route at an ANALYSIS cutoff of 65536.
This changes neither the q38 protocol nor any proof-size/degree parameter.
Arithmetic source only; not compiled under the current user instruction. -/
namespace HegemonCrypto.SmallWood.Mca38RoundByRoundParameters
open scoped BigOperators
set_option autoImplicit false

def domain : Nat := 8388608
def degree : Nat := 405
def threshold : Nat := 65536
def multiplicity : Nat := 5
def xBound : Nat := 327680
def yBound : Nat := 810
def zBound : Nat := 10000

def variableCount : Nat :=
  ∑ j ∈ Finset.range yBound, (xBound - degree*j)*(zBound-j)

def equationCount : Nat :=
  domain * ((multiplicity*(multiplicity+1)/2)*zBound -
    (multiplicity^3-multiplicity)/6)

def labelBudget : Nat :=
  zBound + 2*yBound*zBound + 2*(1+809*yBound)*yBound*zBound +
    (domain*(1618*yBound*zBound+yBound)+(threshold-degree-1))/(threshold-degree) +
    domain*yBound

theorem sum_affine_product (a b c : ℚ) (t : ℕ) :
    (∑ j ∈ Finset.range t, (a - b * (j : ℚ)) * (c - (j : ℚ))) =
      (t : ℚ) * a * c -
      (a + b * c) * (t : ℚ) * ((t : ℚ) - 1) / 2 +
      b * (t : ℚ) * ((t : ℚ) - 1) * (2 * (t : ℚ) - 1) / 6 := by
  induction t with
  | zero => norm_num
  | succ t ih =>
      rw [Finset.sum_range_succ, ih]
      push_cast
      ring

theorem exact_analysis_geometry :
    xBound = multiplicity*threshold ∧
    degree*(yBound-1) < xBound ∧ xBound ≤ degree*yBound ∧
    degree < threshold ∧ threshold < domain := by
  norm_num [domain, degree, threshold, multiplicity, xBound, yBound]

theorem exact_equation_count : equationCount = 1258123427840 := by
  norm_num [equationCount, domain, multiplicity, zBound]

theorem exact_variable_count : variableCount = 1291494765825 := by
  have hc : (variableCount : ℚ) = 1291494765825 := by
    simp only [variableCount, Nat.cast_sum, Nat.cast_mul]
    calc
      _ = ∑ j ∈ Finset.range yBound,
          (327680 - 405 * (j : ℚ)) * (10000 - (j : ℚ)) := by
        apply Finset.sum_congr rfl
        intro j hj
        have hjlt : j < yBound := by simpa using hj
        have hx : degree * j ≤ xBound := by
          norm_num [degree, xBound, yBound] at hjlt ⊢
          omega
        have hz : j ≤ zBound := by
          norm_num [zBound, yBound] at hjlt ⊢
          omega
        rw [Nat.cast_sub hx, Nat.cast_sub hz]
        norm_num [degree, xBound, zBound]
      _ = _ := by
        rw [sum_affine_product]
        norm_num [yBound]
  exact_mod_cast hc

theorem proposed_variable_count_strict_surplus : equationCount < variableCount := by
  rw [exact_equation_count, exact_variable_count]
  norm_num

theorem exact_label_budget : labelBudget = 12310499043179 := by
  norm_num [labelBudget, domain, degree, threshold, yBound, zBound]

end HegemonCrypto.SmallWood.Mca38RoundByRoundParameters
