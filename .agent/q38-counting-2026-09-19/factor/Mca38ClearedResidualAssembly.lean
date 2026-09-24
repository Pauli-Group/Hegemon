import Mca38SharedNumeratorBidegree

namespace HegemonCrypto.SmallWood.Mca38Published
set_option autoImplicit false
noncomputable section

variable {R S : Type*} [CommRing R] [CommRing S]

theorem coefficient_height_mul (P Q : Polynomial (Polynomial R)) (a b : ℕ)
    (hP : ∀ i, (P.coeff i).natDegree ≤ a)
    (hQ : ∀ i, (Q.coeff i).natDegree ≤ b) :
    ∀ i, ((P * Q).coeff i).natDegree ≤ a + b := by
  intro i
  rw [Polynomial.coeff_mul]
  exact Polynomial.natDegree_sum_le_of_forall_le _ _
    (fun j _ => Polynomial.natDegree_mul_le.trans (Nat.add_le_add (hP j.1) (hQ j.2)))

theorem coefficient_height_pow (P : Polynomial (Polynomial R)) (a j : ℕ)
    (hP : ∀ i, (P.coeff i).natDegree ≤ a) :
    ∀ i, ((P ^ j).coeff i).natDegree ≤ j * a := by
  induction j with
  | zero => intro i; simp only [pow_zero, Polynomial.coeff_one]; split_ifs <;> simp
  | succ j ih =>
    simpa only [pow_succ, Nat.succ_mul] using coefficient_height_mul (P ^ j) P (j*a) a ih hP

/-- One explicit polynomial clears every positive coefficient with the same
denominator. Coefficient zero is omitted because the Hensel correction has
constant coefficient zero. -/
def commonHenselNumerator (A : ℕ → Polynomial R) (d : Polynomial R) (N : ℕ) :
    Polynomial (Polynomial R) :=
  ∑ n ∈ Finset.range (N + 1),
    Polynomial.monomial n (if n = 0 then 0 else A n * d ^ ((2*N-1) - (2*n-1)))

theorem commonHenselNumerator_clear (φ : Polynomial R →+* S)
    (A : ℕ → Polynomial R) (d : Polynomial R) (N : ℕ) (p : Polynomial S)
    (hp : p.natDegree ≤ N) (hp0 : p.coeff 0 = 0)
    (hA : ∀ n, 0 < n → n ≤ N → φ (A n) = φ d ^ (2*n-1) * p.coeff n) :
    (commonHenselNumerator A d N).map φ = Polynomial.C (φ d ^ (2*N-1)) * p := by
  classical
  rw [commonHenselNumerator, Polynomial.map_sum]
  conv_rhs => rw [p.as_sum_range' (N+1) (by omega)]
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro n hn
  have hnN : n ≤ N := by simpa using Nat.le_of_lt_succ (Finset.mem_range.mp hn)
  by_cases hn0 : n = 0
  · subst n; simp [hp0]
  · have hnpos : 0 < n := Nat.pos_of_ne_zero hn0
    have he : (2*n-1) + ((2*N-1)-(2*n-1)) = 2*N-1 := by omega
    simp only [if_neg hn0, Polynomial.map_monomial, map_mul, map_pow, hA n hnpos hnN]
    rw [← Polynomial.C_pow, Polynomial.C_mul_monomial]
    congr 1
    rw [mul_right_comm, ← pow_add, he]

theorem commonHenselNumerator_height (A : ℕ → Polynomial R) (d : Polynomial R)
    (D N : ℕ) (hd : d.natDegree ≤ D)
    (hA : ∀ n, 0 < n → n ≤ N → (A n).natDegree ≤ (2*n-1)*D) :
    ∀ i, ((commonHenselNumerator A d N).coeff i).natDegree ≤ (2*N-1)*D := by
  classical
  intro i
  simp only [commonHenselNumerator, Polynomial.finsetSum_coeff]
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro n hn
  have hnN : n ≤ N := Nat.le_of_lt_succ (Finset.mem_range.mp hn)
  by_cases hn0 : n = 0
  · simp [hn0]
  · have hnpos : 0 < n := Nat.pos_of_ne_zero hn0
    simp only [if_neg hn0, Polynomial.coeff_monomial]
    split_ifs
    · have hb := Polynomial.natDegree_mul_le (p := A n)
        (q := d ^ ((2*N-1)-(2*n-1)))
      refine hb.trans ((Nat.add_le_add (hA n hnpos hnN)
        (Polynomial.natDegree_pow_le_of_le _ hd)).trans ?_)
      have he : (2*n-1) + ((2*N-1)-(2*n-1)) = 2*N-1 := by omega
      rw [← Nat.add_mul, he]
    · simp

/-- Homogenized substitution, in the source polynomial ring itself. This
is the actual residual numerator, not an arbitrary obstruction polynomial. -/
def clearedHenselResidual (F : Polynomial (Polynomial (Polynomial R)))
    (Q : Polynomial (Polynomial R)) (d : Polynomial R) (e m : ℕ) :
    Polynomial (Polynomial R) :=
  ∑ j ∈ F.support, Polynomial.C (d ^ (e * (m-j))) * F.coeff j * Q ^ j

theorem clearedHenselResidual_clear (φ : Polynomial R →+* S)
    (F : Polynomial (Polynomial (Polynomial R)))
    (Q : Polynomial (Polynomial R)) (d : Polynomial R) (e m : ℕ)
    (p : Polynomial S) (hm : F.natDegree ≤ m)
    (hQ : Q.map φ = Polynomial.C (φ d ^ e) * p) :
    (clearedHenselResidual F Q d e m).map φ =
      Polynomial.C (φ d ^ (e*m)) * (F.map (Polynomial.mapRingHom φ)).eval p := by
  classical
  rw [clearedHenselResidual, Polynomial.map_sum]
  rw [Polynomial.eval_map, Polynomial.eval₂_eq_sum, Polynomial.sum, Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro j hj
  have hjm : j ≤ m := (Polynomial.le_natDegree_of_mem_supp j hj).trans hm
  have he : e * (m-j) + e*j = e*m := by rw [← Nat.mul_add, Nat.sub_add_cancel hjm]
  simp only [Polynomial.coe_mapRingHom]
  simp only [Polynomial.map_mul, Polynomial.map_C, Polynomial.map_pow,
    map_pow, hQ, mul_pow]
  simp only [← Polynomial.C_pow, ← pow_mul]
  calc
    _ = (Polynomial.C (φ d ^ (e*(m-j))) * Polynomial.C (φ d ^ (e*j))) *
        ((F.coeff j).map φ * p^j) := by ring
    _ = _ := by rw [← Polynomial.C_mul, ← pow_add, he]

theorem clearedHenselResidual_height
    (F : Polynomial (Polynomial (Polynomial R)))
    (Q : Polynomial (Polynomial R)) (d : Polynomial R) (D e m : ℕ)
    (hm : F.natDegree ≤ m) (hd : d.natDegree ≤ D)
    (hF : ∀ j i, ((F.coeff j).coeff i).natDegree ≤ D)
    (hQ : ∀ i, (Q.coeff i).natDegree ≤ e*D) :
    ∀ i, ((clearedHenselResidual F Q d e m).coeff i).natDegree ≤ (1+e*m)*D := by
  classical
  intro i
  simp only [clearedHenselResidual, Polynomial.finsetSum_coeff]
  apply Polynomial.natDegree_sum_le_of_forall_le
  intro j hj
  have hjm : j ≤ m := (Polynomial.le_natDegree_of_mem_supp j hj).trans hm
  have hprod := coefficient_height_mul (F.coeff j) (Q^j) D (j*(e*D))
    (hF j) (coefficient_height_pow Q (e*D) j hQ) i
  rw [mul_assoc, Polynomial.coeff_C_mul]
  refine Polynomial.natDegree_mul_le.trans ((Nat.add_le_add
    (Polynomial.natDegree_pow_le_of_le (e*(m-j)) hd) hprod).trans ?_)
  have he : m-j+j = m := Nat.sub_add_cancel hjm
  calc
    e*(m-j)*D + (D+j*(e*D)) = (1+e*(m-j+j))*D := by ring
    _ ≤ (1+e*m)*D := by simp only [he, le_refl]

end
end HegemonCrypto.SmallWood.Mca38Published
