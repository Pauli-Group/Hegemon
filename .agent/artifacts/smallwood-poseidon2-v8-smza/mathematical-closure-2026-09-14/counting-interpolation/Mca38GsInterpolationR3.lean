import Mathlib.LinearAlgebra.FiniteDimensional.Lemmas
import Mathlib.LinearAlgebra.Dimension.Constructions
import Mathlib.Data.Fintype.BigOperators
import Mathlib.Algebra.BigOperators.Fin
import Mathlib.FieldTheory.Separable
import Mathlib.Algebra.CharP.Defs
import Mathlib.Tactic.NormNum
import Mathlib.Tactic.Ring
import Mathlib.Tactic.Push

/-!
Concrete homogeneous interpolation system for the M=1 proof of BCHKS Theorem 4.6.
This file proves only existence of a nonzero coefficient table satisfying the
published Hasse constraints. It does not assume or prove the final label count.
Prepared source: not yet compiler checked.
-/

namespace HegemonCrypto.SmallWood.Mca38Published

open scoped BigOperators
noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

def n : ℕ := 8388608
def k : ℕ := 405
def cutoff : ℕ := 58288
def multiplicity : ℕ := 64897
def xBound : ℕ := 3782716336
def yBound : ℕ := 9340041
def zBound : ℕ := 29078336404291

/-- A coefficient of X^i Y^j Z^h, with i + k*j < xBound and j+h < zBound. -/
abbrev MonomialIndex :=
  Σ j : Fin yBound, Fin (xBound - k * j.val) × Fin (zBound - j.val)

/-- A Hasse equation at x, derivative (r,s), and coefficient Z^t. -/
abbrev EquationIndex :=
  Fin n × (Σ s : Fin multiplicity,
    Fin (multiplicity - s.val) × Fin (zBound - s.val))

theorem sum_affine_product (a b c : ℚ) (t : ℕ) :
    (∑ j ∈ Finset.range t, (a - b * (j : ℚ)) * (c - (j : ℚ))) =
      (t : ℚ) * a * c -
      (a + b * c) * (t : ℚ) * ((t : ℚ) - 1) / 2 +
      b * (t : ℚ) * ((t : ℚ) - 1) * (2 * (t : ℚ) - 1) / 6 := by
  induction t with
  | zero => norm_num
  | succ t ih =>
      rw [Finset.sum_range_succ, ih]
      push_cast
      ring

theorem sum_fin_affine_product (a b c : ℚ) (t : ℕ) :
    (∑ j : Fin t, (a - b * (j.val : ℚ)) * (c - (j.val : ℚ))) =
      (t : ℚ) * a * c -
      (a + b * c) * (t : ℚ) * ((t : ℚ) - 1) / 2 +
      b * (t : ℚ) * ((t : ℚ) - 1) * (2 * (t : ℚ) - 1) / 6 := by
  calc
    _ = ∑ j ∈ Finset.range t, (a - b * (j : ℚ)) * (c - (j : ℚ)) :=
      Fin.sum_univ_eq_sum_range (fun j : ℕ => (a - b * (j : ℚ)) * (c - (j : ℚ))) t
    _ = _ := sum_affine_product a b c t

theorem monomial_card :
    Fintype.card MonomialIndex = 513679326684233757589887358896 := by
  have hc : (Fintype.card MonomialIndex : ℚ) =
      513679326684233757589887358896 := by
    simp only [MonomialIndex, Fintype.card_sigma, Fintype.card_prod,
      Fintype.card_fin, Nat.cast_sum, Nat.cast_mul]
    calc
      (∑ j : Fin yBound,
        ((xBound - k * j.val : ℕ) : ℚ) * ((zBound - j.val : ℕ) : ℚ)) =
          ∑ j : Fin yBound,
            (3782716336 - 405 * (j.val : ℚ)) *
              (29078336404291 - (j.val : ℚ)) := by
        apply Finset.sum_congr rfl
        intro j _
        have hj : j.val < 9340041 := j.isLt
        have hx : k * j.val ≤ xBound := by unfold k xBound; omega
        have hz : j.val ≤ zBound := by unfold zBound; omega
        rw [Nat.cast_sub hx, Nat.cast_sub hz]
        norm_num [xBound, k, zBound]
      _ = 513679326684233757589887358896 := by
        rw [sum_fin_affine_product]
        norm_num [yBound]
  exact_mod_cast hc

theorem equation_card :
    Fintype.card EquationIndex = 513671410772344328853196374016 := by
  have hc : (Fintype.card EquationIndex : ℚ) =
      513671410772344328853196374016 := by
    simp only [EquationIndex, Fintype.card_prod, Fintype.card_sigma,
      Fintype.card_fin, Nat.cast_mul, Nat.cast_sum]
    have hs :
        (∑ s : Fin multiplicity,
          ((multiplicity - s.val : ℕ) : ℚ) * ((zBound - s.val : ℕ) : ℚ)) =
        ∑ s : Fin multiplicity,
          (64897 - (s.val : ℚ)) * (29078336404291 - (s.val : ℚ)) := by
      apply Finset.sum_congr rfl
      intro s _
      have hm : s.val ≤ multiplicity := Nat.le_of_lt s.isLt
      have hs : s.val < 64897 := s.isLt
      have hz : s.val ≤ zBound := by unfold zBound; omega
      rw [Nat.cast_sub hm, Nat.cast_sub hz]
      norm_num [multiplicity, zBound]
    rw [hs]
    have hs' := sum_fin_affine_product 64897 1 29078336404291 multiplicity
    simp only [one_mul] at hs'
    rw [hs']
    norm_num [n, multiplicity]
  exact_mod_cast hc

theorem strictly_more_unknowns :
    Fintype.card EquationIndex < Fintype.card MonomialIndex := by
  rw [equation_card, monomial_card]
  norm_num

theorem interpolation_surplus :
    Fintype.card MonomialIndex - Fintype.card EquationIndex =
      7915911889428736690984880 := by
  rw [equation_card, monomial_card]

theorem monomial_weighted_degree (v : MonomialIndex) :
    v.2.1.val + k * v.1.val < xBound := by
  have h := v.2.1.isLt
  omega

theorem monomial_z_specialization_degree (v : MonomialIndex) :
    v.1.val + v.2.2.val < zBound := by
  have h := v.2.2.isLt
  omega

theorem exact_support_multiplicity_budget :
    xBound = multiplicity * cutoff := by
  norm_num [xBound, multiplicity, cutoff]

theorem improved_factor_threshold_within_requested_count :
    2 * xBound * yBound ^ 2 * zBound + n * yBound ≤
      19191588994328775603293919496651850544 := by
  norm_num [xBound, yBound, zBound, n]

variable {K : Type*} [Field K]

/-- At this concrete parameter size, every positive-Y-degree irreducible
factor over a characteristic-Goldilocks coefficient field is separable.
The coefficient field may be a rational-function field: perfection is not
assumed. Thus no inseparable-case recursion is needed for this instance. -/
theorem irreducible_small_degree_separable
    [CharP K 18446744069414584321] (f : Polynomial K)
    (hf : Irreducible f) (hdegree : f.natDegree < yBound) :
    f.Separable := by
  apply (Polynomial.separable_iff_derivative_ne_zero hf).mpr
  have hpos : 0 < f.natDegree := hf.natDegree_pos
  have hchar : f.natDegree < 18446744069414584321 := by
    unfold yBound at hdegree
    omega
  have hcast : (f.natDegree : K) ≠ 0 := by
    intro hz
    have hdvd := (CharP.cast_eq_zero_iff K 18446744069414584321
      f.natDegree).mp hz
    have hle := Nat.le_of_dvd hpos hdvd
    omega
  have hlead : f.coeff f.natDegree ≠ 0 := by
    exact Polynomial.leadingCoeff_ne_zero.mpr hf.ne_zero
  intro hzero
  have hcoeff := congrArg (fun p : Polynomial K => p.coeff (f.natDegree - 1)) hzero
  rw [Polynomial.coeff_derivative,
    Nat.sub_add_cancel (by omega : 1 ≤ f.natDegree), Polynomial.coeff_zero] at hcoeff
  have hnat : ((f.natDegree - 1 : ℕ) : K) + 1 = (f.natDegree : K) := by
    simpa only [Nat.cast_add, Nat.cast_one] using
      congrArg (fun n : ℕ => (n : K))
        (Nat.sub_add_cancel (by omega : 1 ≤ f.natDegree))
  rw [hnat] at hcoeff
  exact mul_ne_zero hlead hcast hcoeff

/-- The coefficient of Z^t in the (r,s) Hasse derivative after
Y = U(x) + Z*V(x). Natural binomial coefficients make derivative entries zero
when r>i or s>j. No assumption is made on source words or evaluation points. -/
def hasseCoefficient (point U V : Fin n → K)
    (e : EquationIndex) (v : MonomialIndex) : K :=
  let j := v.1.val
  let i := v.2.1.val
  let h := v.2.2.val
  let s := e.2.1.val
  let r := e.2.2.1.val
  let t := e.2.2.2.val
  if h ≤ t ∧ t - h ≤ j - s then
    (Nat.choose i r : K) * (Nat.choose j s : K) *
      (Nat.choose (j - s) (t - h) : K) *
      point e.1 ^ (i - r) * U e.1 ^ (j - s - (t - h)) * V e.1 ^ (t - h)
  else 0

def hasseSystem (point U V : Fin n → K) :
    (MonomialIndex → K) →ₗ[K] (EquationIndex → K) where
  toFun coeff e := ∑ v, coeff v * hasseCoefficient point U V e v
  map_add' a b := by
    funext e
    simp only [Pi.add_apply, add_mul, Finset.sum_add_distrib]
  map_smul' scalar a := by
    funext e
    simp only [Pi.smul_apply, smul_eq_mul, mul_assoc,
      Finset.mul_sum, RingHom.id_apply]

/-- Generic finite-matrix kernel lemma, kept symbolic to prevent the
elaborator unfolding a gigantic concrete Fin enumeration during conversion. -/
theorem exists_nonzero_matrix_solution {I J : Type*} [Fintype I] [Fintype J]
    (hcard : Fintype.card J < Fintype.card I) (matrix : J → I → K) :
    ∃ coeff : I → K, coeff ≠ 0 ∧ ∀ e, (∑ v, coeff v * matrix e v) = 0 := by
  let L : (I → K) →ₗ[K] (J → K) :=
    { toFun := fun coeff e => ∑ v, coeff v * matrix e v
      map_add' := by
        intro a b
        funext e
        simp only [Pi.add_apply, add_mul, Finset.sum_add_distrib]
      map_smul' := by
        intro scalar a
        funext e
        simp only [Pi.smul_apply, smul_eq_mul, mul_assoc,
          Finset.mul_sum, RingHom.id_apply] }
  have hdim : Module.finrank K (J → K) < Module.finrank K (I → K) := by
    simpa only [Module.finrank_fintype_fun_eq_card] using hcard
  have hk : LinearMap.ker L ≠ ⊥ := LinearMap.ker_ne_bot_of_finrank_lt hdim
  obtain ⟨coeff, hmem, hne⟩ := Submodule.exists_mem_ne_zero_of_ne_bot hk
  refine ⟨coeff, hne, ?_⟩
  have hz : L coeff = 0 := LinearMap.mem_ker.mp hmem
  intro e
  exact congrFun hz e

/-- The first concrete mathematical construction needed by the published
factor argument. This is stronger than a numerical parameter check: every
actual matrix generated from arbitrary point/U/V has a nonzero solution. -/
theorem exists_nonzero_hasse_table (point U V : Fin n → K) :
    ∃ coeff : MonomialIndex → K, coeff ≠ 0 ∧
      ∀ e : EquationIndex,
        (∑ v, coeff v * hasseCoefficient point U V e v) = 0 := by
  exact exists_nonzero_matrix_solution strictly_more_unknowns
    (hasseCoefficient point U V)

end
end HegemonCrypto.SmallWood.Mca38Published


