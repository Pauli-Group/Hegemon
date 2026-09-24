import HegemonCrypto.Goldilocks
import Mathlib.Algebra.Polynomial.Roots
import Mathlib.Data.Rat.Defs
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Positivity

/-!
# Exact finite-field polynomial sampling bound

SmallWood repeatedly reduces an invalid algebraic claim to a nonzero univariate polynomial and
samples a uniform field element.  This module proves the finite counting statement behind those
Schwartz-Zippel steps.  It is independent of Fiat-Shamir and commitments.
-/

namespace HegemonCrypto.FiniteFieldSampling

open Polynomial

variable {F : Type*}
variable [Field F] [Fintype F] [DecidableEq F]

/-- Distinct field elements on which a polynomial evaluates to zero. -/
def rootSet (polynomial : F[X]) : Finset F :=
  Finset.univ.filter fun point => polynomial.eval point = 0

theorem mem_root_set_iff
    (polynomial : F[X])
    (point : F) :
    point ∈ rootSet polynomial ↔ polynomial.eval point = 0 := by
  simp [rootSet]

/-- A nonzero polynomial has at most `natDegree` distinct roots in a field. -/
theorem root_set_card_le_nat_degree
    {polynomial : F[X]}
    (nonzero : polynomial ≠ 0) :
    (rootSet polynomial).card <= polynomial.natDegree := by
  apply Polynomial.card_le_degree_of_subset_roots
  intro point membership
  have evaluatesToZero : polynomial.eval point = 0 := by
    exact (mem_root_set_iff polynomial point).mp
      (by simpa using membership)
  exact (Polynomial.mem_roots nonzero).2 evaluatesToZero

/-- Exact rational probability that one uniform field point is a root. -/
def uniformRootProbability
    (polynomial : F[X]) : Rat :=
  (rootSet polynomial).card / Fintype.card F

theorem uniform_root_probability_nonnegative
    (polynomial : F[X]) :
    0 <= uniformRootProbability polynomial := by
  unfold uniformRootProbability
  exact div_nonneg (by positivity) (by
    have cardPositive : (0 : Nat) < Fintype.card F := Fintype.card_pos
    exact_mod_cast cardPositive.le)

theorem uniform_root_probability_at_most_one
    (polynomial : F[X]) :
    uniformRootProbability polynomial <= 1 := by
  unfold uniformRootProbability
  have cardPositive : (0 : Rat) < Fintype.card F := by
    exact_mod_cast Fintype.card_pos
  rw [div_le_one cardPositive]
  exact_mod_cast Finset.card_le_card (Finset.subset_univ (rootSet polynomial))

/-- Exact Schwartz-Zippel counting bound for one nonzero univariate polynomial. -/
theorem uniform_root_probability_le_degree
    {polynomial : F[X]}
    (nonzero : polynomial ≠ 0) :
    uniformRootProbability polynomial <=
      (polynomial.natDegree : Rat) / Fintype.card F := by
  unfold uniformRootProbability
  exact div_le_div_of_nonneg_right
    (by exact_mod_cast root_set_card_le_nat_degree nonzero)
    (by positivity)

section Goldilocks

open HegemonCrypto.SmallWood
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

theorem goldilocks_card :
    Fintype.card Goldilocks = goldilocksModulus := by
  exact ZMod.card goldilocksModulus

/-- Production-field specialization with the exact Goldilocks denominator. -/
theorem goldilocks_uniform_root_probability_le_degree
    {polynomial : Goldilocks[X]}
    (nonzero : polynomial ≠ 0) :
    uniformRootProbability polynomial <=
      (polynomial.natDegree : Rat) / goldilocksModulus := by
  simpa [goldilocks_card] using
    uniform_root_probability_le_degree nonzero

end Goldilocks

end HegemonCrypto.FiniteFieldSampling
