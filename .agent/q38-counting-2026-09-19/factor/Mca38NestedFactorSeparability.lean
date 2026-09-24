import Mca38NestedFactorCoverage
import Mathlib.RingTheory.Polynomial.GaussLemma
import Mathlib.FieldTheory.Separable
import Mathlib.RingTheory.Polynomial.Resultant.Basic

/-! Separability of actual positive-Y nested factors.

Factorization is in K[Z][X][Y]. Gauss's lemma moves each positive-Y factor
to the fraction field of K[Z][X]; irreducibility and the explicit degree /
characteristic inequality prove separability. The actual leading coefficient
times derivative resultant is therefore nonzero in K[Z][X]. No separability,
regular-point, or exceptional-label-count hypothesis is assumed.
-/
namespace HegemonCrypto.SmallWood.Mca38NestedFactorSeparability
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]
abbrev Coeff (K : Type*) [Field K] := Polynomial (Polynomial K)
abbrev Rat (K : Type*) [Field K] := FractionRing (Coeff K)

theorem actual_factor_divides {F H : Tri (K := K)} (hF : F ≠ 0)
    (member : H ∈ factors F) : H ∣ F :=
  (Multiset.dvd_prod member).trans (factor_product_associated hF).dvd

theorem actual_factor_degree_le {F H : Tri (K := K)} (hF : F ≠ 0)
    (member : H ∈ factors F) : H.natDegree ≤ F.natDegree :=
  Polynomial.natDegree_le_of_dvd (actual_factor_divides hF member) hF

theorem actual_positive_factor_fraction_irreducible {F H : Tri (K := K)}
    (member : H ∈ factors F) (positive : 0 < H.natDegree) :
    Irreducible (H.map (algebraMap (Coeff K) (Rat K))) := by
  have irr := factors_irreducible H member
  exact (Polynomial.IsPrimitive.irreducible_iff_irreducible_map_fraction_map
    (K := Rat K) (irr.isPrimitive (Nat.ne_of_gt positive))).mp irr

theorem irreducible_degree_below_characteristic_separable
    {L : Type*} [Field L] (f : Polynomial L) (irr : Irreducible f)
    (small : f.natDegree < ringChar L) : f.Separable := by
  have positive := irr.natDegree_pos
  have scalar : (f.natDegree : L) ≠ 0 := by
    intro zero
    have divides : ringChar L ∣ f.natDegree :=
      (CharP.cast_eq_zero_iff L (ringChar L) f.natDegree).mp zero
    exact (Nat.not_le_of_lt small) (Nat.le_of_dvd positive divides)
  apply (Polynomial.separable_iff_derivative_ne_zero irr).mpr
  intro derivativeZero
  have coefficient := congrArg
    (fun p : Polynomial L => p.coeff (f.natDegree - 1)) derivativeZero
  rw [Polynomial.coeff_derivative, Polynomial.coeff_zero] at coefficient
  have index : f.natDegree - 1 + 1 = f.natDegree := by omega
  have castIndex : ((f.natDegree - 1 : ℕ) : L) + 1 = (f.natDegree : L) := by
    simpa only [Nat.cast_add, Nat.cast_one] using
      congrArg (fun n : ℕ => (n : L)) index
  rw [index, castIndex] at coefficient
  exact (mul_ne_zero (Polynomial.leadingCoeff_ne_zero.mpr irr.ne_zero) scalar)
    coefficient

theorem actual_positive_factor_separable {F H : Tri (K := K)}
    (hF : F ≠ 0) (member : H ∈ factors F) (positive : 0 < H.natDegree)
    (small : F.natDegree < ringChar (Rat K)) :
    (H.map (algebraMap (Coeff K) (Rat K))).Separable := by
  apply irreducible_degree_below_characteristic_separable
    _ (actual_positive_factor_fraction_irreducible member positive)
  rw [Polynomial.natDegree_map_eq_of_injective
    (IsFractionRing.injective (Coeff K) (Rat K))]
  exact (actual_factor_degree_le hF member).trans_lt small

def regularityObstruction (H : Tri (K := K)) : Coeff K :=
  H.leadingCoeff * H.resultant H.derivative

theorem actual_positive_factor_obstruction_ne_zero {F H : Tri (K := K)}
    (hF : F ≠ 0) (member : H ∈ factors F) (positive : 0 < H.natDegree)
    (small : F.natDegree < ringChar (Rat K)) : regularityObstruction H ≠ 0 := by
  let φ := algebraMap (Coeff K) (Rat K)
  have injective : Function.Injective φ := IsFractionRing.injective (Coeff K) (Rat K)
  have separable := actual_positive_factor_separable hF member positive small
  have coprime : IsCoprime (H.map φ) (H.derivative.map φ) := by
    simpa only [Polynomial.derivative_map] using
      ((Polynomial.separable_def _).mp separable)
  have result : φ (H.resultant H.derivative) ≠ 0 := by
    simpa only [Polynomial.natDegree_map_eq_of_injective injective,
      Polynomial.resultant_map_map] using
      (Polynomial.resultant_ne_zero (H.map φ) (H.derivative.map φ) coprime)
  have nonzero : H.resultant H.derivative ≠ 0 := by
    intro zero
    apply result
    rw [zero, map_zero]
  exact mul_ne_zero (Polynomial.leadingCoeff_ne_zero.mpr (factors_nonzero member)) nonzero

end
end HegemonCrypto.SmallWood.Mca38NestedFactorSeparability
