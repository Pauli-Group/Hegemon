import Mca38FiniteFactorLocalization
import Mca38HenselTransferR2

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R S : Type*} [CommRing R] [CommRing S]

def coefficientOrigin (f : Polynomial (Polynomial R)) : Polynomial R :=
  f.map (Polynomial.evalRingHom 0)

theorem coefficientOrigin_map (ψ : R →+* S) (f : Polynomial (Polynomial R)) :
    coefficientOrigin (f.map (Polynomial.mapRingHom ψ)) =
      (coefficientOrigin f).map ψ := by
  ext j
  simp [coefficientOrigin, Polynomial.coeff_map, Polynomial.eval_zero_map]

theorem eval_constant_coefficientOrigin (f : Polynomial (Polynomial R)) (a : R) :
    (f.eval (Polynomial.C a)).eval 0 = (coefficientOrigin f).eval a := by
  have h := Polynomial.eval_map_apply (p := f)
    (f := Polynomial.evalRingHom (0 : R)) (Polynomial.C a)
  simpa only [coefficientOrigin, Polynomial.coe_evalRingHom, Polynomial.eval_C] using h.symm

/-- The source quotient, localized at its actual derivative residue. -/
abbrev NewtonFactorLocalization (f : Polynomial (Polynomial R)) (H : Polynomial R) :=
  Localization.Away (AdjoinRoot.mk H (coefficientOrigin f).derivative)

def localizedCoefficientMap (f : Polynomial (Polynomial R)) (H : Polynomial R) :
    R →+* NewtonFactorLocalization f H :=
  (algebraMap (AdjoinRoot H) (NewtonFactorLocalization f H)).comp (AdjoinRoot.of H)

def localizedRoot (f : Polynomial (Polynomial R)) (H : Polynomial R) :
    NewtonFactorLocalization f H :=
  algebraMap (AdjoinRoot H) (NewtonFactorLocalization f H) (AdjoinRoot.root H)

theorem localized_eval_mk (f : Polynomial (Polynomial R)) (H p : Polynomial R) :
    (p.map (localizedCoefficientMap f H)).eval (localizedRoot f H) =
      algebraMap (AdjoinRoot H) (NewtonFactorLocalization f H) (AdjoinRoot.mk H p) := by
  rw [Polynomial.eval_map]
  change p.eval₂
    ((algebraMap (AdjoinRoot H) (NewtonFactorLocalization f H)).comp (AdjoinRoot.of H))
    ((algebraMap (AdjoinRoot H) (NewtonFactorLocalization f H)) (AdjoinRoot.root H)) = _
  rw [← Polynomial.hom_eval₂]
  congr 1
  rw [← AdjoinRoot.algebraMap_eq, ← Polynomial.aeval_def, AdjoinRoot.aeval_eq]

/-- The initial Newton validity is proved in the finite localized quotient
itself. It therefore survives every valid specialization of that ring,
without first requiring an injection into the algebraic function field. -/
theorem actual_localized_newton_start
    (f : Polynomial (Polynomial R)) (H : Polynomial R)
    (hdiv : H ∣ coefficientOrigin f) :
    NewtonValid
      (f.map (Polynomial.mapRingHom (localizedCoefficientMap f H)))
      Polynomial.X 1
      (Polynomial.C (localizedRoot f H),
       Polynomial.C (IsLocalization.Away.invSelf
         (S := NewtonFactorLocalization f H) (AdjoinRoot.mk H (coefficientOrigin f).derivative))) := by
  let F := f.map (Polynomial.mapRingHom (localizedCoefficientMap f H))
  let a := localizedRoot f H
  have hroot : (F.eval (Polynomial.C a)).eval 0 = 0 := by
    rw [eval_constant_coefficientOrigin]
    change (coefficientOrigin (f.map
      (Polynomial.mapRingHom (localizedCoefficientMap f H)))).eval (localizedRoot f H) = 0
    rw [coefficientOrigin_map, localized_eval_mk, AdjoinRoot.mk_eq_zero.mpr hdiv, map_zero]
  have hd : (F.derivative.eval (Polynomial.C a)).eval 0 =
      algebraMap (AdjoinRoot H) (NewtonFactorLocalization f H)
        (AdjoinRoot.mk H (coefficientOrigin f).derivative) := by
    rw [eval_constant_coefficientOrigin]
    change (coefficientOrigin ((f.map
      (Polynomial.mapRingHom (localizedCoefficientMap f H))).derivative)).eval
        (localizedRoot f H) = _
    rw [Polynomial.derivative_map, coefficientOrigin_map]
    have horigin : coefficientOrigin f.derivative = (coefficientOrigin f).derivative := by
      simp only [coefficientOrigin, Polynomial.derivative_map]
    rw [horigin, localized_eval_mk]
  constructor
  · simpa only [pow_one, Polynomial.X_dvd_iff, Polynomial.coeff_zero_eq_eval_zero] using hroot
  · simp only [pow_one, Polynomial.X_dvd_iff, Polynomial.coeff_zero_eq_eval_zero,
      Polynomial.eval_sub, Polynomial.eval_mul, Polynomial.eval_C, Polynomial.eval_one]
    change (F.derivative.eval (Polynomial.C a)).eval 0 *
      IsLocalization.Away.invSelf (S := NewtonFactorLocalization f H)
        (AdjoinRoot.mk H (coefficientOrigin f).derivative) - 1 = 0
    rw [hd, IsLocalization.Away.mul_invSelf, sub_self]

end
end HegemonCrypto.SmallWood.Mca38Published
