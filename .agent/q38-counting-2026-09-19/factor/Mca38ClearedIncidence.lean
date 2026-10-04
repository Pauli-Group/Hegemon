import Mca38ActualResidualNorm
import Mca38LocalizedResidualCount
import Mca38BivariateHeightInterface

/-! Actual polynomial obstruction for a nonidentical position of a finite
Newton branch. No evaluation homomorphism from K(Z) to K is used. The
specializations take place in the finite quotient/localization. -/
namespace HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false

section Numerator
variable {R S : Type*} [CommRing R] [CommRing S]

def clearedIncidence (N : Polynomial (Polynomial R)) (d : Polynomial R)
    (e : Nat) (x line : R) : Polynomial R :=
  N.eval (Polynomial.C x) - d^e * Polynomial.C line

theorem cleared_incidence_identity
    (φ : Polynomial R →+* S) (N : Polynomial (Polynomial R))
    (d : Polynomial R) (p : Polynomial S) (e : Nat) (x line : R)
    (cleared : N.map φ = Polynomial.C (φ d ^ e) * p) :
    φ (clearedIncidence N d e x line) =
      φ d ^ e * (p.eval (φ (Polynomial.C x)) - φ (Polynomial.C line)) := by
  have evaluated : φ (N.eval (Polynomial.C x)) =
      φ d ^ e * p.eval (φ (Polynomial.C x)) := by
    rw [← Polynomial.eval_map_apply, cleared,
      Polynomial.eval_mul, Polynomial.eval_C]
  simp only [clearedIncidence, map_sub, map_mul, map_pow, evaluated]
  ring

theorem constant_eval_natDegree_le (N : Polynomial (Polynomial R)) (x : R)
    (bound : Nat) (coefficients : ∀ i, (N.coeff i).natDegree ≤ bound) :
    (N.eval (Polynomial.C x)).natDegree ≤ bound := by
  rw [Polynomial.eval_eq_sum, Polynomial.sum]
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro i _
  apply Polynomial.natDegree_mul_le.trans
  simpa only [← Polynomial.C_pow, Polynomial.natDegree_C, add_zero] using coefficients i

end Numerator

section Counting
variable {K L : Type*} [Field K] [Field L]

/-- A scalar localized residue has a genuine nonzero resultant obstruction.
This is the single-position counterpart of the polynomial-residual count. -/
theorem localized_scalar_incidence_count
    (H d B : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    (injective : Function.Injective φ) [Fact (Irreducible (H.map φ))]
    (denominator : AdjoinRoot.mk (H.map φ) (d.map φ) ≠ 0)
    (r : FiniteFactorLocalization H d) (e DT DZ DH : Nat)
    (cleared : algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d)
        (AdjoinRoot.mk H B) =
      (algebraMap (AdjoinRoot H) (FiniteFactorLocalization H d)
        (AdjoinRoot.mk H d))^e * r)
    (nonidentical : finiteFactorGenericMap H d φ denominator r ≠ 0)
    (degreeT : B.natDegree ≤ DT)
    (degreeZ : ∀ j, (B.coeff j).natDegree ≤ DZ)
    (factorZ : ∀ j, (H.coeff j).natDegree ≤ DH)
    (labels : Finset K)
    (specialized : ∀ z ∈ labels, ∃ t : K,
      ∃ root : H.eval₂ (Polynomial.evalRingHom z) t = 0,
      ∃ simple : d.eval₂ (Polynomial.evalRingHom z) t ≠ 0,
      finiteFactorSpecialization H d z t root simple r = 0) :
    labels.card ≤ H.natDegree * DZ + DT * DH := by
  have generic : AdjoinRoot.mk (H.map φ) (B.map φ) ≠ 0 := by
    have identity := congrArg (finiteFactorGenericMap H d φ denominator) cleared
    rw [finiteFactorGenericMap_numerator, map_mul, map_pow,
      finiteFactorGenericMap_numerator] at identity
    rw [identity]
    exact mul_ne_zero (pow_ne_zero _ denominator) nonidentical
  have count := actual_quotient_residual_exception_count H B φ injective
    (Fact.out : Irreducible (H.map φ)) generic DH DZ factorZ degreeZ labels (by
      intro z hz
      obtain ⟨t, root, simple, zero⟩ := specialized z hz
      exact ⟨t, root, localized_residual_zero_forces_numerator_zero
        H d B r e cleared z t root simple zero⟩)
  exact count.trans (Nat.add_le_add_left (Nat.mul_le_mul_right DH degreeT) _)

end Counting
end
end HegemonCrypto.SmallWood.Mca38Published
