import Mca38HenselRootShift

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R : Type*} [CommRing R]

/-- A sharp source-height bound for the actual dependent-variable shift.
The j-th shifted coefficient uses at most m-j powers of the represented
starting root. In particular the derivative coefficient saves one power. -/
theorem henselRootShift_coefficient_height
    (F : Polynomial (Polynomial (Polynomial R))) (c : Polynomial R)
    (D Dc m : ℕ) (hm : F.natDegree ≤ m)
    (hF : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ D)
    (hc : c.natDegree ≤ Dc) :
    ∀ j i, (((henselRootShift F c).coeff j).coeff i).natDegree ≤ D + (m-j)*Dc := by
  classical
  intro j i
  rw [henselRootShift, Polynomial.taylor_coeff, Polynomial.eval_eq_sum, Polynomial.sum,
    Polynomial.finsetSum_coeff]
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro r hr
  have hrm : r ≤ m-j :=
    (Polynomial.le_natDegree_of_mem_supp r hr).trans
      ((Polynomial.natDegree_hasseDeriv_le F j).trans (Nat.sub_le_sub_right hm j))
  rw [← Polynomial.C_pow, Polynomial.coeff_mul_C, Polynomial.hasseDeriv_coeff,
    Polynomial.coeff_natCast_mul]
  have hterm : (((r+j).choose j : Polynomial R) * (F.coeff (r+j)).coeff i).natDegree ≤ D := by
    exact Polynomial.natDegree_mul_le.trans (by simpa using hF (r+j) i)
  exact Polynomial.natDegree_mul_le.trans (Nat.add_le_add hterm
    (Polynomial.natDegree_pow_le_of_le r hc |>.trans (Nat.mul_le_mul_right Dc hrm)))

/-- The derivative representative's sharper height pays for restoring the
constant root in a common numerator, at the unchanged Hensel exponent. -/
theorem constant_root_common_denominator_budget (m e : ℕ)
    (hm : 0 < m) (he : 0 < e) : 1 + e*(m-1) ≤ e*m := by
  have h : m-1+1=m := by omega
  calc
    1+e*(m-1) ≤ e+e*(m-1) := Nat.add_le_add_right he _
    _ = e*(m-1+1) := by ring
    _ = e*m := by rw [h]

end
end HegemonCrypto.SmallWood.Mca38Published
