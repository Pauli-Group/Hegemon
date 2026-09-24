import Mca38LocalizedResidualCount

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K L : Type*} [Field K] [Field L]

/-- Irreducibility plus a nonvanishing degree scalar establishes separability;
the derivative is not assumed nonzero. The scalar premise follows from the
characteristic bound for each actual factor's Y degree. -/
theorem irreducible_separable_of_degree_scalar
    (f : Polynomial L) (hirr : Irreducible f) (hc : (f.natDegree : L) ≠ 0) :
    f.Separable := by
  apply (Polynomial.separable_iff_derivative_ne_zero hirr).mpr
  intro hd
  have hn := hirr.natDegree_pos
  have hcoeff := congrArg (fun p : Polynomial L => p.coeff (f.natDegree-1)) hd
  rw [Polynomial.coeff_derivative, Polynomial.coeff_zero] at hcoeff
  have he : f.natDegree-1+1=f.natDegree := by omega
  rw [he] at hcoeff
  have hscalar : ((f.natDegree-1 : ℕ) : L) + 1 = (f.natDegree : L) := by
    simpa only [Nat.cast_add, Nat.cast_one] using congrArg (fun n : ℕ => (n : L)) he
  rw [hscalar] at hcoeff
  exact (mul_ne_zero (Polynomial.leadingCoeff_ne_zero.mpr hirr.ne_zero) hc) hcoeff

/-- The denominator inverted by the actual Newton start is nonzero in the
generic irreducible quotient because the original polynomial is separable. -/
theorem actual_derivative_generic_nonzero
    (G H : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    (hirr : Irreducible (H.map φ)) (hdiv : H ∣ G)
    (hsep : (G.map φ).Separable) :
    AdjoinRoot.mk (H.map φ) (G.derivative.map φ) ≠ 0 := by
  intro hz
  have hH := Polynomial.map_dvd φ hdiv
  have hd := AdjoinRoot.mk_eq_zero.mp hz
  have hcop : IsCoprime (G.map φ) (G.derivative.map φ) := by
    simpa only [Polynomial.derivative_map] using
      ((Polynomial.separable_def _).mp hsep)
  exact hirr.not_isUnit (hcop.isUnit_of_dvd' hH hd)

/-- Outside the explicit specialization obstruction, every specialized root
of any actual divisor has a nonvanishing Newton denominator. -/
theorem actual_derivative_specialized_nonzero
    (G H : Polynomial (Polynomial K)) (hdiv : H ∣ G)
    (hpositive : 0 < G.natDegree) (z t : K)
    (hz : (simpleSpecializationException G).eval z ≠ 0)
    (hroot : H.eval₂ (Polynomial.evalRingHom z) t = 0) :
    G.derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0 := by
  have hsep := (specialization_simple_of_exception_ne_zero G hpositive z hz).2
  have hG : G.eval₂ (Polynomial.evalRingHom z) t = 0 := by
    obtain ⟨q, rfl⟩ := hdiv
    rw [Polynomial.eval₂_mul, hroot, zero_mul]
  have hr : (specializeCoefficientVariable G z).eval t = 0 := by
    simpa only [specializeCoefficientVariable, Polynomial.eval_map] using hG
  have hd := hsep.eval₂_derivative_ne_zero (RingHom.id K) (by simpa using hr)
  simpa only [Polynomial.eval₂_id, specializeCoefficientVariable,
    Polynomial.derivative_map, Polynomial.eval_map] using hd

end
end HegemonCrypto.SmallWood.Mca38Published
