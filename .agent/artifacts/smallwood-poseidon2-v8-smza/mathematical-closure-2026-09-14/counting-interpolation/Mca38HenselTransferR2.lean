import Mca38FiniteHenselR2

/-! Finite Hensel lifting commutes with coefficient specialization and follows
any actual polynomial root with the same starting residue. These are algebraic
identities, not a bound on how many specializations survive. -/

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false

variable {R : Type*} [CommRing R]

theorem newtonStep_tracks_root (f : Polynomial R) (π : R) (m : ℕ)
    (s : R × R) (r : R) (hr : f.eval r = 0)
    (hclose : π ^ m ∣ r - s.1)
    (hinverse : π ^ m ∣ f.derivative.eval s.1 * s.2 - 1) :
    π ^ (m + m) ∣ r - (newtonStep f s).1 := by
  obtain ⟨u, hu⟩ := hclose
  obtain ⟨v, hv⟩ := hinverse
  obtain ⟨c, hc⟩ := f.exists_mul_sq_add_linear_part_eq_eval_add s.1 (r - s.1)
  have hsum : c * (r - s.1) ^ 2 +
      f.derivative.eval s.1 * (r - s.1) + f.eval s.1 = 0 := by
    have harg : s.1 + (r - s.1) = r := by ring
    rw [harg, hr] at hc
    exact hc
  have hfa : f.eval s.1 =
      -(c * (r - s.1) ^ 2 + f.derivative.eval s.1 * (r - s.1)) := by
    calc
      f.eval s.1 =
          (c * (r - s.1) ^ 2 + f.derivative.eval s.1 * (r - s.1) + f.eval s.1) -
          (c * (r - s.1) ^ 2 + f.derivative.eval s.1 * (r - s.1)) := by ring
      _ = _ := by rw [hsum]; ring
  refine ⟨-(u * v + s.2 * c * u ^ 2), ?_⟩
  calc
    r - (newtonStep f s).1 =
        -(r - s.1) * (f.derivative.eval s.1 * s.2 - 1) -
        s.2 * c * (r - s.1) ^ 2 := by
      dsimp [newtonStep]
      rw [hfa]
      ring
    _ = _ := by rw [hu, hv, pow_add]; ring

theorem newtonIterate_tracks_root (f : Polynomial R) (π : R)
    (s : R × R) (hs : NewtonValid f π 1 s)
    (r : R) (hr : f.eval r = 0) (hclose : π ∣ r - s.1) (t : ℕ) :
    π ^ (2 ^ t) ∣ r - (newtonIterate f s t).1 := by
  induction t with
  | zero => simpa only [pow_zero, pow_one, newtonIterate] using hclose
  | succ t ih =>
      have h := newtonStep_tracks_root f π (2 ^ t) (newtonIterate f s t) r hr ih
        (newtonIterate_valid f π s hs t).2
      simpa only [newtonIterate, pow_succ, mul_two] using h

variable {S : Type*} [CommRing S]

theorem newtonStep_map (φ : R →+* S) (f : Polynomial R) (s : R × R) :
    newtonStep (f.map φ) (φ s.1, φ s.2) =
      (φ (newtonStep f s).1, φ (newtonStep f s).2) := by
  have hd : (f.derivative.map φ).eval (φ s.1 - φ s.2 * φ (f.eval s.1)) =
      φ (f.derivative.eval (s.1 - s.2 * f.eval s.1)) := by
    rw [← map_mul, ← map_sub, Polynomial.eval_map_apply]
  simp only [newtonStep, Polynomial.derivative_map,
    Polynomial.eval_map_apply, map_sub, map_mul, map_ofNat]
  rw [hd]

theorem newtonIterate_map (φ : R →+* S) (f : Polynomial R) (s : R × R) (t : ℕ) :
    newtonIterate (f.map φ) (φ s.1, φ s.2) t =
      (φ (newtonIterate f s t).1, φ (newtonIterate f s t).2) := by
  induction t with
  | zero => rfl
  | succ t ih =>
      simp only [newtonIterate, ih, newtonStep_map]

section StartingPoint

variable {K : Type*} [Field K]

/-- Evaluate the coefficient polynomials at X=0, leaving Y formal. -/
noncomputable def residuePolynomial (f : Polynomial (Polynomial K)) : Polynomial K :=
  f.map (Polynomial.evalRingHom 0)

theorem eval_const_residue (f : Polynomial (Polynomial K)) (a : K) :
    (f.eval (Polynomial.C a)).eval 0 = (residuePolynomial f).eval a := by
  have h := Polynomial.eval_map_apply (p := f)
    (f := Polynomial.evalRingHom (0 : K)) (Polynomial.C a)
  simpa only [residuePolynomial, Polynomial.coe_evalRingHom,
    Polynomial.eval_C] using h.symm

/-- A genuine simple root of R(0,Y) supplies the concrete initial state.
In the published application K is the field adjoining a root of the
irreducible starting factor; no pre-existing Newton-validity assumption is
needed beyond the actual root and nonzero derivative. -/
theorem constant_start_valid (f : Polynomial (Polynomial K)) (a : K)
    (hroot : (residuePolynomial f).eval a = 0)
    (hsimple : (residuePolynomial f).derivative.eval a ≠ 0) :
    NewtonValid f Polynomial.X 1
      (Polynomial.C a, Polynomial.C (((residuePolynomial f).derivative.eval a)⁻¹)) := by
  have hroot' : (f.eval (Polynomial.C a)).eval 0 = 0 :=
    (eval_const_residue f a).trans hroot
  have hderivative : (f.derivative.eval (Polynomial.C a)).eval 0 =
      (residuePolynomial f).derivative.eval a := by
    rw [eval_const_residue]
    simp only [residuePolynomial, Polynomial.derivative_map]
  constructor
  · simpa only [pow_one, Polynomial.X_dvd_iff,
      Polynomial.coeff_zero_eq_eval_zero] using hroot'
  · simp only [pow_one, Polynomial.X_dvd_iff,
      Polynomial.coeff_zero_eq_eval_zero, Polynomial.eval_sub,
      Polynomial.eval_mul, Polynomial.eval_C, Polynomial.eval_one,
      hderivative, mul_inv_cancel₀ hsimple, sub_self]

end StartingPoint

end HegemonCrypto.SmallWood.Mca38Published

