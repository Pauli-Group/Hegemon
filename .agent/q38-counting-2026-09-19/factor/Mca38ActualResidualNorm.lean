import Mca38UniformSpecialization

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K L : Type*} [Field K] [Field L]

/-- The two actual Sylvester column blocks give the usual resultant height
bound, without assuming a determinant-degree estimate for this matrix. -/
theorem resultant_two_coefficient_heights
    (H B : Polynomial (Polynomial K)) (DH DB m n : ℕ)
    (hH : ∀ j, (H.coeff j).natDegree ≤ DH)
    (hB : ∀ j, (B.coeff j).natDegree ≤ DB) :
    (H.resultant B m n).natDegree ≤ m * DB + n * DH := by
  let heights : Fin (m + n) → ℕ := Fin.addCases (fun _ => DB) (fun _ => DH)
  have he : ∀ i j, ((Polynomial.sylvester H B m n) i j).natDegree ≤ heights j := by
    intro i j
    refine Fin.addCases (fun j => ?_) (fun j => ?_) j
    · simp only [Polynomial.sylvester, Matrix.of_apply, Fin.addCases_left, heights]
      split_ifs
      · exact hB _
      · simp
    · simp only [Polynomial.sylvester, Matrix.of_apply, Fin.addCases_right, heights]
      split_ifs
      · exact hH _
      · simp
  have hd := elimination_determinant_natDegree
    (Polynomial.sylvester H B m n) heights he
  simpa [Polynomial.resultant, heights, Fin.sum_univ_add] using hd

/-- A nonzero actual residue in the irreducible quotient yields a nonzero
resultant polynomial in the base parameter. Nonvanishing is proved from the
quotient equality criterion, irreducibility, and resultant coprimality. -/
theorem resultant_ne_zero_of_actual_quotient_residue
    (H B : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    (hinj : Function.Injective φ) (hirred : Irreducible (H.map φ))
    (hresidue : AdjoinRoot.mk (H.map φ) (B.map φ) ≠ 0) :
    H.resultant B ≠ 0 := by
  have hnotdvd : ¬ (H.map φ) ∣ B.map φ := by
    intro h
    exact hresidue (AdjoinRoot.mk_eq_zero.mpr h)
  have hcop := hirred.coprime_iff_not_dvd.mpr hnotdvd
  have hnonzero := Polynomial.resultant_ne_zero (H.map φ) (B.map φ) hcop
  simp only [Polynomial.natDegree_map_eq_of_injective hinj,
    Polynomial.resultant_map_map] at hnonzero
  intro hz
  apply hnonzero
  rw [hz, map_zero]

/-- This uses the source Bezout identity, so specialized degrees are allowed
to drop. Every actual common specialized root annihilates the resultant. -/
theorem resultant_vanishes_at_common_specialized_root
    (H B : Polynomial (Polynomial K)) (hpositive : 0 < H.natDegree)
    (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hB : B.eval₂ (Polynomial.evalRingHom z) t = 0) :
    (H.resultant B).eval z = 0 := by
  obtain ⟨a, b, _, _, hbez⟩ := Polynomial.exists_mul_add_mul_eq_C_resultant
    H B (le_refl _) (le_refl _) (Or.inl (Nat.ne_of_gt hpositive))
  have h := congrArg (fun p => Polynomial.eval₂ (Polynomial.evalRingHom z) t p) hbez
  simp only [Polynomial.eval₂_add, Polynomial.eval₂_mul, hH, hB, zero_mul,
    zero_add, Polynomial.eval₂_C, Polynomial.coe_evalRingHom] at h
  exact h.symm

/-- An actual nonzero quotient residual is converted into a concrete
polynomial obstruction, its proved degree, and an actual exceptional-label
bound. The common-root hypotheses are the specialization facts still to be
obtained from finite localization/root tracking. -/
theorem actual_quotient_residual_exception_count
    (H B : Polynomial (Polynomial K)) (φ : Polynomial K →+* L)
    (hinj : Function.Injective φ) (hirred : Irreducible (H.map φ))
    (hresidue : AdjoinRoot.mk (H.map φ) (B.map φ) ≠ 0)
    (DH DB : ℕ) (hH : ∀ j, (H.coeff j).natDegree ≤ DH)
    (hB : ∀ j, (B.coeff j).natDegree ≤ DB)
    (labels : Finset K)
    (hlabels : ∀ z ∈ labels, ∃ t : K,
      H.eval₂ (Polynomial.evalRingHom z) t = 0 ∧
      B.eval₂ (Polynomial.evalRingHom z) t = 0) :
    labels.card ≤ H.natDegree * DB + B.natDegree * DH := by
  have hpositive : 0 < H.natDegree := by
    simpa only [Polynomial.natDegree_map_eq_of_injective hinj] using hirred.natDegree_pos
  have hnonzero := resultant_ne_zero_of_actual_quotient_residue H B φ hinj hirred hresidue
  have hcard : labels.card ≤ (H.resultant B).natDegree := by
    apply Polynomial.card_le_degree_of_subset_roots
    intro z hz
    obtain ⟨t, htH, htB⟩ := hlabels z hz
    exact (Polynomial.mem_roots hnonzero).mpr
      (resultant_vanishes_at_common_specialized_root H B hpositive z t htH htB)
  exact hcard.trans (resultant_two_coefficient_heights H B DH DB
    H.natDegree B.natDegree hH hB)

end
end HegemonCrypto.SmallWood.Mca38Published
