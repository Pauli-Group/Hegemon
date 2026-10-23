import Mca38LocalizedSourceSpecialization
import Mca38LocalizedNewtonTruncation

/-!
# Generic finite Newton recovery and the HTLC degree-9933 instance

The response is the actual finite Newton iterate, reduced modulo X^(D+1).
The iteration precision is an explicit premise, D+1 <= 2^steps. The concrete
HTLC instance uses 14 iterations and degree 9933. Its specialization theorem
uses the existing finite quotient/localization and the actual source polynomial.
No field-completion, assumed response identity, global label-count, or production
activation premise is introduced here.
-/
namespace HegemonCrypto.SmallWood.NativeHtlcGlobalNewton

open HegemonCrypto.SmallWood.Mca38Published

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 20000

variable {R : Type*} [CommRing R]

/-- The actual Newton iterate truncated at the requested response degree. -/
def finiteNewtonResponse (D steps : ℕ) (F : Polynomial (Polynomial R))
    (s : Polynomial R × Polynomial R) : Polynomial R :=
  (newtonIterate F s steps).1 %ₘ (Polynomial.X ^ (D + 1))

/-- Truncation preserves the starting root and the certified root congruence.
This works over any nontrivial commutative ring, including the finite localization. -/
theorem finiteNewtonResponse_properties [Nontrivial R]
    (D steps : ℕ) (enough : D + 1 ≤ 2 ^ steps)
    (F : Polynomial (Polynomial R)) (s : Polynomial R × Polynomial R)
    (hs : NewtonValid F Polynomial.X 1 s) :
    (finiteNewtonResponse D steps F s).natDegree ≤ D ∧
    (finiteNewtonResponse D steps F s).coeff 0 = s.1.coeff 0 ∧
    Polynomial.X ^ (D + 1) ∣ F.eval (finiteNewtonResponse D steps F s) := by
  let a := (newtonIterate F s steps).1
  have hmod : Polynomial.X ^ (D + 1) ∣ finiteNewtonResponse D steps F s - a :=
    Polynomial.dvd_modByMonic_sub a (Polynomial.X ^ (D + 1))
  have hpow : (Polynomial.X : Polynomial R) ∣ Polynomial.X ^ (D + 1) := by
    simpa only [pow_one] using pow_dvd_pow (Polynomial.X : Polynomial R)
      (Nat.succ_le_succ (Nat.zero_le D))
  refine ⟨?_, ?_, ?_⟩
  · have hne : (Polynomial.X ^ (D + 1) : Polynomial R) ≠ 1 := by
      intro h
      have hn := congrArg Polynomial.natDegree h
      simp only [Polynomial.natDegree_X_pow, Polynomial.natDegree_one] at hn
      omega
    have hd := Polynomial.natDegree_modByMonic_lt a
      (Polynomial.monic_X_pow (D + 1)) hne
    rw [Polynomial.natDegree_X_pow] at hd
    exact Nat.le_of_lt_succ hd
  · have hi := newtonIterate_preserves_root_mod_one F Polynomial.X s hs steps
    have hclose := dvd_add (dvd_trans hpow hmod) hi
    have hz : (Polynomial.X : Polynomial R) ∣ finiteNewtonResponse D steps F s - s.1 := by
      simpa only [a, sub_add_sub_cancel] using hclose
    rw [Polynomial.X_dvd_iff, Polynomial.coeff_sub] at hz
    exact sub_eq_zero.mp hz
  · have hvalid := (newtonIterate_valid F Polynomial.X s hs steps).1
    have ha : Polynomial.X ^ (D + 1) ∣ F.eval a :=
      dvd_trans (pow_dvd_pow Polynomial.X enough) hvalid
    have hdiff := dvd_trans hmod (Polynomial.sub_dvd_eval_sub
      (finiteNewtonResponse D steps F s) a F)
    have hadd := dvd_add hdiff ha
    simpa only [sub_add_cancel] using hadd

variable {K : Type*} [Field K]

/-- Every genuine bounded root with the same initial value is the specialization
of this same finite Newton response; the root is not a supplied recovery function. -/
theorem specialized_response_eq_finiteNewtonResponse
    (ψ : R →+* K) (D steps : ℕ) (enough : D + 1 ≤ 2 ^ steps)
    (F : Polynomial (Polynomial R)) (s : Polynomial R × Polynomial R)
    (hs : NewtonValid F Polynomial.X 1 s)
    (P : Polynomial K) (hP : P.natDegree ≤ D)
    (hroot : (F.map (Polynomial.mapRingHom ψ)).eval P = 0)
    (hconstant : P.eval 0 = ψ (s.1.eval 0)) :
    P = (finiteNewtonResponse D steps F s).map ψ := by
  let φ : Polynomial R →+* Polynomial K := Polynomial.mapRingHom ψ
  have hs' : NewtonValid (F.map φ) Polynomial.X 1 (φ s.1, φ s.2) := by
    simpa only [φ, Polynomial.coe_mapRingHom, Polynomial.map_X] using
      newtonValid_map φ F Polynomial.X 1 s hs
  have hclose : Polynomial.X ∣ P - φ s.1 := by
    rw [Polynomial.X_dvd_iff, Polynomial.coeff_zero_eq_eval_zero,
      Polynomial.eval_sub]
    change P.eval 0 - (s.1.map ψ).eval 0 = 0
    rw [Polynomial.eval_zero_map, hconstant, sub_self]
  have htrack := newtonIterate_tracks_root (F.map φ) Polynomial.X
    (φ s.1, φ s.2) hs' P hroot hclose steps
  have htrackMapped :
      (newtonIterate (F.map φ) (φ s.1, φ s.2) steps).1 =
        (newtonIterate F s steps).1.map ψ := by
    simpa only [φ, Polynomial.coe_mapRingHom] using
      congrArg Prod.fst (newtonIterate_map φ F s steps)
  rw [htrackMapped] at htrack
  have htruncated : (Polynomial.X ^ (D + 1) : Polynomial K) ∣
      P - (newtonIterate F s steps).1.map ψ :=
    dvd_trans (pow_dvd_pow Polynomial.X enough) htrack
  have hmod := Polynomial.modByMonic_eq_of_dvd_sub
    (Polynomial.monic_X_pow (D + 1)) htruncated
  have hPmod : P %ₘ (Polynomial.X ^ (D + 1)) = P := by
    apply (Polynomial.modByMonic_eq_self_iff (Polynomial.monic_X_pow (D + 1))).mpr
    calc
      P.degree ≤ (D : WithBot ℕ) := Polynomial.degree_le_of_natDegree_le hP
      _ < (Polynomial.X ^ (D + 1) : Polynomial K).degree := by
        rw [Polynomial.degree_X_pow]
        exact_mod_cast Nat.lt_succ_self D
  rw [hPmod] at hmod
  rw [finiteNewtonResponse, Polynomial.map_modByMonic ψ
    (Polynomial.monic_X_pow (D + 1)), Polynomial.map_pow, Polynomial.map_X]
  exact hmod

/-- Source degree 9933 needs precision 9934; fourteen iterations certify 16384. -/
def finiteNewtonResponse9933 (F : Polynomial (Polynomial R))
    (s : Polynomial R × Polynomial R) : Polynomial R :=
  finiteNewtonResponse 9933 14 F s

theorem finiteNewtonResponse9933_properties [Nontrivial R]
    (F : Polynomial (Polynomial R)) (s : Polynomial R × Polynomial R)
    (hs : NewtonValid F Polynomial.X 1 s) :
    (finiteNewtonResponse9933 F s).natDegree ≤ 9933 ∧
    (finiteNewtonResponse9933 F s).coeff 0 = s.1.coeff 0 ∧
    Polynomial.X ^ 9934 ∣ F.eval (finiteNewtonResponse9933 F s) := by
  simpa only [finiteNewtonResponse9933, show (9933 : ℕ) + 1 = 9934 from rfl] using
    finiteNewtonResponse_properties 9933 14 (by norm_num) F s hs

/-- Exact source-polynomial recovery through the existing finite localization.
Only genuine response/root/initial-value premises are accepted. -/
theorem actual_source_response_tracks_localized_newton9933
    (F : Polynomial (Polynomial (Polynomial K))) (H : Polynomial (Polynomial K))
    (hdiv : H ∣ coefficientOrigin F) (z t : K)
    (hH : H.eval₂ (Polynomial.evalRingHom z) t = 0)
    (hd : (coefficientOrigin F).derivative.eval₂ (Polynomial.evalRingHom z) t ≠ 0)
    (P : Polynomial K) (hP : P.natDegree ≤ 9933)
    (hroot : (F.map (Polynomial.mapRingHom (Polynomial.evalRingHom z))).eval P = 0)
    (hconstant : P.eval 0 = t) :
    P = (finiteNewtonResponse9933 (actualLocalizedNewtonPolynomial F H)
      (actualLocalizedNewtonState F H)).map
        (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd) := by
  apply specialized_response_eq_finiteNewtonResponse
    (finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd)
    9933 14 (by norm_num)
    (actualLocalizedNewtonPolynomial F H) (actualLocalizedNewtonState F H)
    (actual_localized_newton_start F H hdiv) P hP
  · rw [actualLocalizedNewtonPolynomial_specializes_to_source]
    exact hroot
  · change P.eval 0 =
      finiteFactorSpecialization H (coefficientOrigin F).derivative z t hH hd
        ((Polynomial.C (localizedRoot F H)).eval 0)
    rw [Polynomial.eval_C, finiteFactorSpecialization_localizedRoot, hconstant]

end
end HegemonCrypto.SmallWood.NativeHtlcGlobalNewton
