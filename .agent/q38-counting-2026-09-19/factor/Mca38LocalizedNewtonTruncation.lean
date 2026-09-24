import Mca38LocalizedResponseTracking

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R : Type*} [CommRing R]

theorem newtonIterate_preserves_root_mod_one (F : Polynomial R) (π : R)
    (s : R × R) (hs : NewtonValid F π 1 s) (t : ℕ) :
    π ∣ (newtonIterate F s t).1-s.1 := by
  induction t with
  | zero => simp [newtonIterate]
  | succ t ih =>
    have hstep := newtonStep_preserves_root_mod F π (2^t) (newtonIterate F s t)
      (newtonIterate_valid F π s hs t)
    have hpow : π ∣ π^(2^t) := by
      simpa only [pow_one] using pow_dvd_pow π
        (one_le_pow₀ (by norm_num : 1 ≤ (2 : ℕ)))
    have hadd := dvd_add (dvd_trans hpow hstep) ih
    simpa only [newtonIterate, sub_add_sub_cancel] using hadd

set_option maxRecDepth 20000 in
/-- Truncating the actual localized Newton iterate preserves the needed
finite root congruence, its represented constant root, and degree405.
The target need not be a field or domain. -/
theorem finiteNewtonResponse405_properties [Nontrivial R]
    (F : Polynomial (Polynomial R)) (s : Polynomial R × Polynomial R)
    (hs : NewtonValid F Polynomial.X 1 s) :
    (finiteNewtonResponse405 F s).natDegree ≤ 405 ∧
    (finiteNewtonResponse405 F s).coeff 0 = s.1.coeff 0 ∧
    Polynomial.X^406 ∣ F.eval (finiteNewtonResponse405 F s) := by
  let a := (newtonIterate F s 9).1
  have hmod : Polynomial.X^406 ∣ finiteNewtonResponse405 F s-a :=
    Polynomial.dvd_modByMonic_sub a (Polynomial.X^406)
  have hpow : (Polynomial.X : Polynomial R) ∣ Polynomial.X^406 := by
    simpa only [pow_one] using pow_dvd_pow (Polynomial.X : Polynomial R)
      (by decide : 1 ≤ 406)
  refine ⟨?_, ?_, ?_⟩
  · have hne : (Polynomial.X^406 : Polynomial R) ≠ 1 := by
      intro h
      have hn := congrArg Polynomial.natDegree h
      norm_num at hn
    have hd := Polynomial.natDegree_modByMonic_lt a (Polynomial.monic_X_pow 406) hne
    rw [Polynomial.natDegree_X_pow] at hd
    exact Nat.le_of_lt_succ hd
  · have hi := newtonIterate_preserves_root_mod_one F Polynomial.X s hs 9
    have hclose := dvd_add (dvd_trans hpow hmod) hi
    have hz : (Polynomial.X : Polynomial R) ∣ finiteNewtonResponse405 F s-s.1 := by
      simpa only [a, sub_add_sub_cancel] using hclose
    rw [Polynomial.X_dvd_iff, Polynomial.coeff_sub] at hz
    exact sub_eq_zero.mp hz
  · have hvalid := (newtonIterate_valid F Polynomial.X s hs 9).1
    have ha : Polynomial.X^406 ∣ F.eval a :=
      dvd_trans (pow_dvd_pow Polynomial.X (by decide : 406 ≤ 512)) hvalid
    have hdiff := dvd_trans hmod (Polynomial.sub_dvd_eval_sub
      (finiteNewtonResponse405 F s) a F)
    have hadd := dvd_add hdiff ha
    simpa only [sub_add_cancel] using hadd

end
end HegemonCrypto.SmallWood.Mca38Published
