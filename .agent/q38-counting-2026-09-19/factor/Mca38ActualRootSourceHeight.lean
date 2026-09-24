import Mca38ActualRootSource

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {K : Type*} [CommRing K]

theorem coefficientVariableSwap_C (p : Polynomial K) :
    coefficientVariableSwap (Polynomial.C p) = p.map Polynomial.C := by
  simp [coefficientVariableSwap]

theorem coefficientVariableSwap_X :
    coefficientVariableSwap (Polynomial.X : Polynomial (Polynomial K)) =
      Polynomial.C Polynomial.X := by
  simp [coefficientVariableSwap]

theorem actualRootSource_natDegree_le
    (F : Polynomial (Polynomial (Polynomial K))) (m : ℕ) (hm : F.natDegree ≤ m) :
    (actualRootSource F).natDegree ≤ m :=
  Polynomial.natDegree_map_le.trans hm

/-- The formal starting-root variable was absent from the original source,
so its j-th shifted coefficient has T degree at most m-j. -/
theorem actualRootSource_shift_T_height
    (F : Polynomial (Polynomial (Polynomial K))) (m : ℕ) (hm : F.natDegree ≤ m) :
    ∀ j i, (((henselRootShift (actualRootSource F) Polynomial.X).coeff j).coeff i).natDegree ≤ m-j := by
  have h := henselRootShift_coefficient_height (actualRootSource F) Polynomial.X 0 1 m
    (actualRootSource_natDegree_le F m hm)
    (by intro j i; simp [actualRootSource, Polynomial.coeff_map])
    Polynomial.natDegree_X_le
  simpa only [zero_add, Nat.mul_one] using h

/-- Swapping T and Z in the source coefficients proves the simultaneous Z
height for the very same shifted polynomial. The shift root T has Z degree0. -/
theorem actualRootSource_shift_Z_height
    (F : Polynomial (Polynomial (Polynomial K))) (m Z : ℕ) (hm : F.natDegree ≤ m)
    (hF : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ Z) :
    ∀ j i, (coefficientVariableSwap
      (((henselRootShift (actualRootSource F) Polynomial.X).coeff j).coeff i)).natDegree ≤ Z := by
  let σ : Polynomial (Polynomial K) →+* Polynomial (Polynomial K) := coefficientVariableSwap
  let G := (actualRootSource F).map (Polynomial.mapRingHom σ)
  have hGdeg : G.natDegree ≤ m :=
    Polynomial.natDegree_map_le.trans (actualRootSource_natDegree_le F m hm)
  have hG : ∀ j i, ((G.coeff j).coeff i).natDegree ≤ Z := by
    intro j i
    simp only [G, Polynomial.coeff_map, Polynomial.coe_mapRingHom]
    change (σ (((actualRootSource F).coeff j).coeff i)).natDegree ≤ Z
    simp only [actualRootSource, Polynomial.coeff_map, Polynomial.coe_mapRingHom]
    change (coefficientVariableSwap (Polynomial.C ((F.coeff j).coeff i))).natDegree ≤ Z
    rw [coefficientVariableSwap_C]
    exact Polynomial.natDegree_map_le.trans (hF j i)
  have hc : (σ (Polynomial.X : Polynomial (Polynomial K))).natDegree ≤ 0 := by
    simp only [σ, coefficientVariableSwap_X, Polynomial.natDegree_C, le_refl]
  have hh := henselRootShift_coefficient_height G (σ Polynomial.X) Z 0 m hGdeg hG hc
  have hmap : (henselRootShift (actualRootSource F) Polynomial.X).map
      (Polynomial.mapRingHom σ) = henselRootShift G (σ Polynomial.X) := by
    simp only [henselRootShift, Polynomial.map_taylor, Polynomial.coe_mapRingHom,
      Polynomial.map_C, G]
  intro j i
  have h := hh j i
  rw [← hmap] at h
  simpa only [Polynomial.coeff_map, Polynomial.coe_mapRingHom, Nat.mul_zero, add_zero, σ] using h

end
end HegemonCrypto.SmallWood.Mca38Published
