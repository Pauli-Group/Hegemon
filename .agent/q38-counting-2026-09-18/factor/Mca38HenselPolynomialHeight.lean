import Mca38HenselActualRecurrenceR3
import Mca38FiniteHeightInduction
import Mathlib.Algebra.Polynomial.Div

/-! Apply numerator-height induction to a genuine finite polynomial root
approximation, with all coefficient recurrences derived, not assumed. -/

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false

/-- A shifted simple-root approximation through order N has numerator
height linear in each order. F's outer variables are Y then X, and its
coefficient polynomials are the height variable. The homomorphism can be
the map to the algebraic function field, or a valid localization map. -/
theorem finite_polynomial_hensel_height
    {R S : Type*} [CommRing R] [CommRing S] [IsDomain S]
    (φ : Polynomial R →+* S)
    (F : Polynomial (Polynomial (Polynomial R))) (p : Polynomial S) (D N : ℕ)
    (hcoeff : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ D)
    (hd : φ ((F.coeff 1).coeff 0) ≠ 0)
    (hp : p.coeff 0 = 0)
    (hroot : Polynomial.X ^ (N + 1) ∣
      (F.map (Polynomial.mapRingHom φ)).eval p) :
    ∀ n, 0 < n → n ≤ N → ∃ A : Polynomial R,
      A.natDegree ≤ (2 * n - 1) * D ∧
      φ A = φ ((F.coeff 1).coeff 0) ^ (2 * n - 1) * p.coeff n := by
  let f : Polynomial (Polynomial S) := F.map (Polynomial.mapRingHom φ)
  have hmap : ∀ j i, (f.coeff j).coeff i = φ ((F.coeff j).coeff i) := by
    intro j i
    simp only [f, Polynomial.coeff_map, Polynomial.coe_mapRingHom]
  have hfd : (f.coeff 1).coeff 0 ≠ 0 := by rwa [hmap]
  apply exists_hensel_numerator_through_order φ ((F.coeff 1).coeff 0) p.coeff
    (henselRecurrenceIndices f)
    (fun _ t => (F.coeff t.1).coeff (henselIndexOrder t))
    (fun _ => henselIndexOrder) (fun _ => henselIndexList) D N
    hd (hcoeff 1 0)
  · intro n hn hnN t ht
    exact hcoeff _ _
  · intro n hn hnN t ht
    exact (henselRecurrenceIndices_spec f n hn t ht).1
  · intro n hn hnN t ht
    exact (henselRecurrenceIndices_spec f n hn t ht).2.1
  · intro n hn hnN t ht
    exact (henselRecurrenceIndices_spec f n hn t ht).2.2
  · intro n hn hnN
    have hz : (f.eval p).coeff n = 0 :=
      (Polynomial.X_pow_dvd_iff.mp hroot) n (Nat.lt_succ_of_le hnN)
    have h := hensel_actual_recurrence f p n hn hp hfd hz
    simpa only [henselIndexCoefficient, hmap] using h

end HegemonCrypto.SmallWood.Mca38Published
