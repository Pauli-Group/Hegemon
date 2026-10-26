import HegemonCrypto.NativeHtlcGlobalLocal

/-! Arbitrary-support composition for the 327,680 round-by-round system. -/
namespace HegemonCrypto.SmallWood.NativeHtlcGlobal
open scoped BigOperators
noncomputable section
set_option autoImplicit false

open HegemonCrypto.SmallWood.NativeHtlcParameters
open HegemonCrypto.SmallWood.NativeHtlcInterpolation
variable {K : Type*} [Field K]

def supportMultiplicityDivisor (point : Fin domain → K) (S : Finset (Fin domain)) :
    Polynomial K := ∏ a ∈ S,
      (Polynomial.X - Polynomial.C (point a)) ^
        NativeHtlcParameters.multiplicity

theorem supportMultiplicityDivisor_natDegree
    (point : Fin domain → K) (S : Finset (Fin domain)) :
    (supportMultiplicityDivisor point S).natDegree = multiplicity * S.card := by
  unfold supportMultiplicityDivisor
  rw [Polynomial.natDegree_prod_of_monic (s := S)
    (f := fun a => (Polynomial.X - Polynomial.C (point a)) ^
      NativeHtlcParameters.multiplicity)
    (fun a _ => (Polynomial.monic_X_sub_C (point a)).pow
      NativeHtlcParameters.multiplicity)]
  simp [Polynomial.natDegree_pow, Nat.mul_comm]

theorem actual_support_multiplicity
    (c : CoefficientIndex → K) (point U V : Fin domain → K)
    (hsolve : ∀ e : EquationIndex,
      (∑ v, c v * hasseCoefficient point U V e v) = 0)
    (z : K) (P : Polynomial K) (S : Finset (Fin domain))
    (hinj : Set.InjOn point (S : Set (Fin domain)))
    (hmatch : ∀ a ∈ S, P.eval (point a) = U a + z * V a) :
    supportMultiplicityDivisor point S ∣ specializedInterpolant c z P := by
  unfold supportMultiplicityDivisor
  apply Finset.prod_dvd_of_coprime
  · intro a ha b hb hab
    have hp : point a ≠ point b := fun heq => hab (hinj ha hb heq)
    exact (Polynomial.isCoprime_X_sub_C_of_isUnit_sub
      (sub_ne_zero_of_ne hp).isUnit).pow
  · intro a ha
    exact actual_local_multiplicity c point U V hsolve z P a (hmatch a ha)

theorem actual_specialization_eq_zero_on_threshold_support
    (c : CoefficientIndex → K) (point U V : Fin domain → K)
    (hsolve : ∀ e : EquationIndex,
      (∑ v, c v * hasseCoefficient point U V e v) = 0)
    (z : K) (P : Polynomial K) (hP : P.natDegree ≤ degree)
    (S : Finset (Fin domain)) (hcard : threshold ≤ S.card)
    (hinj : Set.InjOn point (S : Set (Fin domain)))
    (hmatch : ∀ a ∈ S, P.eval (point a) = U a + z * V a) :
    specializedInterpolant c z P = 0 := by
  apply specializedInterpolant_eq_zero_of_large_divisor c z P
    (supportMultiplicityDivisor point S) hP
  · exact actual_support_multiplicity c point U V hsolve z P S hinj hmatch
  · rw [supportMultiplicityDivisor_natDegree]
    exact Nat.mul_le_mul_left multiplicity hcard

end
end HegemonCrypto.SmallWood.NativeHtlcGlobal
