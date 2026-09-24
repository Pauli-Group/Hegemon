import Mca38ActualFullNumerator
import Mca38ClearedIncidence

/-! The actual incidence numerator lives in K[Z][T], while the full
Newton numerator lives in K[Z][T][X]. Both heights refer to the SAME
polynomial, not to two unrelated supplied obstructions. -/
namespace HegemonCrypto.SmallWood.Mca38ActualNonaffineBranchCount
open HegemonCrypto.SmallWood.Mca38Published
noncomputable section
set_option autoImplicit false

variable {K : Type*} [Field K]

def affineLine (u v : K) : Polynomial K :=
  Polynomial.C u + Polynomial.X * Polynomial.C v

def branchIncidence (N : Polynomial (Polynomial (Polynomial K)))
    (d : Polynomial (Polynomial K)) (x u v : K) : Polynomial (Polynomial K) :=
  clearedIncidence N d 809 (Polynomial.C x) (affineLine u v)

set_option maxRecDepth 40000 in
theorem affineLine_degree (u v : K) : (affineLine u v).natDegree ≤ 1 := by
  apply (Polynomial.natDegree_add_le _ _).trans
  apply max_le
  · simp
  · exact Polynomial.natDegree_mul_le.trans (by simp)

set_option maxRecDepth 40000 in
theorem branchIncidence_T_height
    (N : Polynomial (Polynomial (Polynomial K)))
    (d : Polynomial (Polynomial K)) (x u v : K) (m : Nat)
    (hN : ∀ i, (N.coeff i).natDegree ≤ 809*m) (hd : d.natDegree ≤ m) :
    (branchIncidence N d x u v).natDegree ≤ 809*m := by
  unfold branchIncidence clearedIncidence
  apply (Polynomial.natDegree_sub_le _ _).trans
  apply max_le
  · exact constant_eval_natDegree_le N (Polynomial.C x) (809*m) hN
  · calc
      (d^809 * Polynomial.C (affineLine u v)).natDegree ≤
          (d^809).natDegree + (Polynomial.C (affineLine u v)).natDegree :=
        Polynomial.natDegree_mul_le
      _ ≤ 809*m := by
        rw [Polynomial.natDegree_C, add_zero]
        exact Polynomial.natDegree_pow_le.trans (Nat.mul_le_mul_left 809 hd)

theorem swap_eval_constant
    (N : Polynomial (Polynomial (Polynomial K))) (x : K) :
    coefficientVariableSwap (N.eval (Polynomial.C (Polynomial.C x))) =
      (N.map coefficientVariableSwap).eval (Polynomial.C (Polynomial.C x)) := by
  rw [← Polynomial.eval_map_apply]
  congr 1
  simp only [coefficientVariableSwap_C, Polynomial.map_C]

set_option maxRecDepth 40000 in
theorem branchIncidence_Z_height
    (N : Polynomial (Polynomial (Polynomial K)))
    (d : Polynomial (Polynomial K)) (x u v : K) (Z : Nat)
    (hN : ∀ i, (coefficientVariableSwap (N.coeff i)).natDegree ≤ 809*Z)
    (hd : (coefficientVariableSwap d).natDegree ≤ Z) :
    (coefficientVariableSwap (branchIncidence N d x u v)).natDegree ≤ 809*Z+1 := by
  unfold branchIncidence clearedIncidence
  rw [map_sub, map_mul, map_pow, swap_eval_constant, coefficientVariableSwap_C]
  apply (Polynomial.natDegree_sub_le _ _).trans
  apply max_le
  · exact (constant_eval_natDegree_le (N.map coefficientVariableSwap)
      (Polynomial.C x) (809*Z) (by simpa only [Polynomial.coeff_map] using hN)).trans
      (Nat.le_add_right _ _)
  · calc
      ((coefficientVariableSwap d)^809 * (affineLine u v).map Polynomial.C).natDegree ≤
          ((coefficientVariableSwap d)^809).natDegree +
            ((affineLine u v).map Polynomial.C).natDegree := Polynomial.natDegree_mul_le
      _ ≤ 809*Z+1 := Nat.add_le_add
        (Polynomial.natDegree_pow_le.trans (Nat.mul_le_mul_left 809 hd))
        (Polynomial.natDegree_map_le.trans (affineLine_degree u v))

/-- The incidence obstruction is derived from the existing actual Newton
numerator. Its scalar localized residue is the literal pointwise mismatch. -/
theorem actual_incidence_numerator
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    [Nontrivial (NewtonFactorLocalization F H)]
    (m Z : Nat) (hmpos : 0 < m) (hm : F.natDegree ≤ m)
    (hF : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ Z)
    (hdiv : H ∣ coefficientOrigin F) :
    ∃ N : Polynomial (Polynomial (Polynomial K)),
      (∀ i, (N.coeff i).natDegree ≤ 809*m) ∧
      (∀ i, (coefficientVariableSwap (N.coeff i)).natDegree ≤ 809*Z) ∧
      ∀ x u v : K,
        actualRootSourceMap F H
          (branchIncidence N (coefficientOrigin F).derivative x u v) =
        (actualRootSourceMap F H (coefficientOrigin F).derivative)^809 *
          ((finiteNewtonResponse405 (actualLocalizedNewtonPolynomial F H)
            (actualLocalizedNewtonState F H)).eval
              (actualRootSourceMap F H (Polynomial.C (Polynomial.C x))) -
            actualRootSourceMap F H (Polynomial.C (affineLine u v))) := by
  obtain ⟨N, hNT, hNZ, cleared⟩ := actual_full_newton_numerator F H m Z hmpos hm hF hdiv
  refine ⟨N, hNT, hNZ, ?_⟩
  intro x u v
  exact cleared_incidence_identity (actualRootSourceMap F H) N
    (coefficientOrigin F).derivative _ 809 (Polynomial.C x) (affineLine u v) cleared

end
end HegemonCrypto.SmallWood.Mca38ActualNonaffineBranchCount
