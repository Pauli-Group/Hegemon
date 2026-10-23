import Mathlib.LinearAlgebra.Lagrange

/-!
# Native HTLC PCS mask algebra

This isolated research module models the width-two branch of `pcs_commit` in
`circuits/transaction/src/smallwood_engine.rs`: at packing 64 and opening count
6, coin `z[k]` is inserted in first-column row `64+k` and subtracted in
last-column row `delta+k`. The nonlinear quotient has degree 74 and delta 59;
the linear polynomial has degree 132 and delta 1. Each role has five polynomials.
The witness degree is 69, width one, with no PCS column-mask coins.

The principal endpoint `masking_exists_unique` proves that, at six distinct
nonzero points over any field, every sixty-word last-column observation vector
has exactly one sixty-word mask vector for every fixed unmasked offset. This is
an algebraic bijection, proved using Lagrange interpolation, not a numerical
rank test. The source-dimension certificate is only a separate arithmetic check.

This file does not prove that Rust implements this model, that its challenge
sampler always supplies distinct nonzero points, that its coins are independent
uniform field elements, or that all other transcript components are independent
of these coins. It is not a complete PCS/HTLC zero-knowledge or QROM theorem and
confers no production activation authority. No RP05 fixed-shape receipt is used.
-/

set_option autoImplicit false

namespace HegemonCrypto.NativeHtlcPcs
open Polynomial

abbrev Coins (F : Type*) := Fin 6 → F

noncomputable def coinPoly {F : Type*} [Field F] (z : Coins F) : F[X] :=
  ((Polynomial.degreeLTEquiv F 6).symm z).1

@[simp] theorem coinPoly_coeff {F : Type*} [Field F] (z : Coins F) (i : Fin 6) :
    (coinPoly z).coeff i = z i := by
  exact congrFun ((Polynomial.degreeLTEquiv F 6).apply_symm_apply z) i

theorem coinPoly_degree_lt {F : Type*} [Field F] (z : Coins F) :
    (coinPoly z).degree < 6 :=
  Polynomial.mem_degreeLT.mp ((Polynomial.degreeLTEquiv F 6).symm z).2

/-- The six input words are the six ordinary monomial coefficients. -/
theorem coinPoly_eq_sum {F : Type*} [Field F] (z : Coins F) :
    coinPoly z = ∑ i : Fin 6, monomial i (z i) := rfl

theorem coinPoly_eval_sum {F : Type*} [Field F] (z : Coins F) (r : F) :
    (coinPoly z).eval r = ∑ i : Fin 6, z i * r ^ i.val := by
  simp [coinPoly_eq_sum, Polynomial.eval_finsetSum]

theorem coinPoly_coeff_outside {F : Type*} [Field F] (z : Coins F)
    (j : ℕ) (hj : 6 ≤ j) : (coinPoly z).coeff j = 0 := by
  exact coeff_eq_zero_of_degree_lt ((coinPoly_degree_lt z).trans_le
    (WithBot.coe_le_coe.mpr hj))

noncomputable def evaluationEquiv {F : Type*} [Field F]
    (r : Fin 6 → F) (hd : Function.Injective r) :
    Polynomial.degreeLT F 6 ≃ₗ[F] (Fin 6 → F) where
  toFun p i := p.1.eval (r i)
  map_add' p q := by ext i; simp
  map_smul' a p := by ext i; simp
  invFun y := ⟨Lagrange.interpolate Finset.univ r y,
    Polynomial.mem_degreeLT.mpr (by
      simpa using Lagrange.degree_interpolate_lt (s := (Finset.univ : Finset (Fin 6))) y hd.injOn)⟩
  left_inv p := by
    apply Subtype.ext
    exact (Lagrange.eq_interpolate hd.injOn (by
      simpa using Polynomial.mem_degreeLT.mp p.2)).symm
  right_inv y := by
    ext i
    exact Lagrange.eval_interpolate_at_node y hd.injOn (Finset.mem_univ i)

noncomputable def coinEvaluationEquiv {F : Type*} [Field F]
    (r : Fin 6 → F) (hd : Function.Injective r) : Coins F ≃ₗ[F] (Fin 6 → F) :=
  (Polynomial.degreeLTEquiv F 6).symm.trans (evaluationEquiv r hd)

noncomputable def lastColumnMask {F : Type*} [Field F] (delta : ℕ) (z : Coins F) : F[X] :=
  -(X ^ delta * coinPoly z)

/-- The source subtracts `z[open_idx]` at row `delta + open_idx`. -/
@[simp] theorem lastColumnMask_coeff {F : Type*} [Field F]
    (delta : ℕ) (z : Coins F) (i : Fin 6) :
    (lastColumnMask delta z).coeff (delta + i) = -(z i) := by
  rw [lastColumnMask, coeff_neg, Nat.add_comm delta i.val, coeff_X_pow_mul, coinPoly_coeff]

/-- The source zeroes rows below `delta`; the mask has no contribution there. -/
theorem lastColumnMask_coeff_below {F : Type*} [Field F]
    (delta : ℕ) (z : Coins F) (j : ℕ) (hj : j < delta) :
    (lastColumnMask delta z).coeff j = 0 := by
  simp [lastColumnMask, Polynomial.coeff_X_pow_mul', Nat.not_le.mpr hj]

/-- The source has exactly six row corrections, with no later mask coefficients. -/
theorem lastColumnMask_coeff_above {F : Type*} [Field F]
    (delta : ℕ) (z : Coins F) (j : ℕ) (hj : delta + 6 ≤ j) :
    (lastColumnMask delta z).coeff j = 0 := by
  have hd : delta ≤ j := (Nat.le_add_right delta 6).trans hj
  have hc : 6 ≤ j - delta := (Nat.le_sub_iff_add_le hd).mpr (by simpa [Nat.add_comm] using hj)
  simp [lastColumnMask, Polynomial.coeff_X_pow_mul', hd, coinPoly_coeff_outside z _ hc]

noncomputable def firstColumnMask {F : Type*} [Field F] (z : Coins F) : F[X] :=
  X ^ 64 * coinPoly z

/-- The source places the same coin in first-column row `64 + open_idx`. -/
@[simp] theorem firstColumnMask_coeff {F : Type*} [Field F]
    (z : Coins F) (i : Fin 6) :
    (firstColumnMask z).coeff (64 + i) = z i := by
  simp [firstColumnMask, Nat.add_comm]

/-- The correlated column masks cancel in the packed polynomial. -/
theorem packed_mask_cancellation {F : Type*} [Field F]
    (delta : ℕ) (hd : delta ≤ 64) (z : Coins F) :
    firstColumnMask z + X ^ (64 - delta) * lastColumnMask delta z = 0 := by
  simp only [firstColumnMask, lastColumnMask, mul_neg, ← mul_assoc, ← pow_add,
    Nat.sub_add_cancel hd, add_neg_cancel]

@[simp] theorem lastColumnMask_eval {F : Type*} [Field F]
    (delta : ℕ) (z : Coins F) (r : F) :
    (lastColumnMask delta z).eval r = -(r ^ delta) * (coinPoly z).eval r := by
  simp [lastColumnMask]

noncomputable def lastColumnMap {F : Type*} [Field F]
    (delta : ℕ) (r : Fin 6 → F) : Coins F →ₗ[F] (Fin 6 → F) where
  toFun z i := -(r i ^ delta) * (coinPoly z).eval (r i)
  map_add' z w := by
    ext i
    simp [coinPoly, mul_add]
  map_smul' a z := by
    ext i
    simp [coinPoly, mul_left_comm]

theorem lastColumnMap_bijective {F : Type*} [Field F]
    (delta : ℕ) (r : Fin 6 → F) (hd : Function.Injective r)
    (hn : ∀ i, r i ≠ 0) : Function.Bijective (lastColumnMap delta r) := by
  let E := coinEvaluationEquiv r hd
  have hw (i : Fin 6) : -(r i ^ delta) ≠ 0 := neg_ne_zero.mpr (pow_ne_zero _ (hn i))
  constructor
  · intro z w h
    apply E.injective
    funext i
    apply mul_left_cancel₀ (hw i)
    exact congrFun h i
  · intro y
    refine ⟨E.symm (fun i => y i / -(r i ^ delta)), ?_⟩
    funext i
    change -(r i ^ delta) * E (E.symm (fun i => y i / -(r i ^ delta))) i = y i
    rw [E.apply_symm_apply]
    simp only [div_eq_mul_inv]
    rw [mul_left_comm, mul_inv_cancel₀ (hw i), mul_one]

/-- Explicit source-map formula in terms of the six sampled coins. -/
theorem lastColumnMap_apply {F : Type*} [Field F]
    (delta : ℕ) (r : Fin 6 → F) (z : Coins F) (i : Fin 6) :
    lastColumnMap delta r z i = -(r i ^ delta) * ∑ k : Fin 6, z k * r i ^ k.val := by
  change -(r i ^ delta) * (coinPoly z).eval (r i) = _
  rw [coinPoly_eval_sum]

noncomputable def lastColumnEquiv {F : Type*} [Field F]
    (delta : ℕ) (r : Fin 6 → F) (hd : Function.Injective r)
    (hn : ∀ i, r i ≠ 0) : Coins F ≃ₗ[F] (Fin 6 → F) :=
  LinearEquiv.ofBijective (lastColumnMap delta r) (lastColumnMap_bijective delta r hd hn)

/-- Integer formulas in `SmallwoodConfig::new_with_profile` for this candidate. -/
def sourceWidth (degree : ℕ) : ℕ := (degree + 1 - 6 + 63) / 64

def sourceDelta (degree : ℕ) : ℕ := 64 * sourceWidth degree + 6 - (degree + 1)

/-- Dimension checks, separate from the generic algebraic mask theorem. -/
theorem source_dimensions :
    64 + 6 - 1 = 69 ∧
    2 * (64 + 6 - 1) - 64 = 74 ∧
    (64 + 6 - 1) + (64 - 1) = 132 ∧
    sourceWidth 69 = 1 ∧ sourceDelta 69 = 0 ∧
    sourceWidth 74 = 2 ∧ sourceDelta 74 = 59 ∧
    sourceWidth 132 = 2 ∧ sourceDelta 132 = 1 ∧
    5 * 6 * (2 - 1) + 5 * 6 * (2 - 1) = 60 := by decide

theorem nonlinear_mask_bijective {F : Type*} [Field F]
    (r : Fin 6 → F) (hd : Function.Injective r) (hn : ∀ i, r i ≠ 0) :
    Function.Bijective (lastColumnMap 59 r) :=
  lastColumnMap_bijective 59 r hd hn

theorem linear_mask_bijective {F : Type*} [Field F]
    (r : Fin 6 → F) (hd : Function.Injective r) (hn : ∀ i, r i ≠ 0) :
    Function.Bijective (lastColumnMap 1 r) :=
  lastColumnMap_bijective 1 r hd hn

/-- Role 0 is nonlinear; role 1 is linear. Each role has rho=5 polynomials. -/
def roleDelta (role : Fin 2) : ℕ := if role = 0 then 59 else 1

abbrev FamilyCoins (F : Type*) := Fin 2 → Fin 5 → Coins F

theorem family_coin_coordinates : Fintype.card (Fin 2 × Fin 5 × Fin 6) = 60 := by decide

noncomputable def familyMap {F : Type*} [Field F]
    (r : Fin 6 → F) (z : FamilyCoins F) : FamilyCoins F :=
  fun role poly => lastColumnMap (roleDelta role) r (z role poly)

/-- The ten independent six-coin masks jointly give a bijection on sixty field words. -/
theorem familyMap_bijective {F : Type*} [Field F]
    (r : Fin 6 → F) (hd : Function.Injective r) (hn : ∀ i, r i ≠ 0) :
    Function.Bijective (familyMap r) := by
  constructor
  · intro z w h
    funext role poly
    apply (lastColumnMap_bijective (roleDelta role) r hd hn).injective
    exact congrFun (congrFun h role) poly
  · intro y
    refine ⟨fun role poly => (lastColumnEquiv (roleDelta role) r hd hn).symm
      (y role poly), ?_⟩
    funext role poly
    exact (lastColumnEquiv (roleDelta role) r hd hn).apply_symm_apply (y role poly)

/-- An arbitrary fixed unmasked last-column evaluation is an additive translation. -/
noncomputable def maskedObservations {F : Type*} [Field F]
    (r : Fin 6 → F) (base z : FamilyCoins F) : FamilyCoins F :=
  base + familyMap r z

/-- Every last-column observation vector has exactly one coin vector, for every base. -/
theorem maskedObservations_bijective {F : Type*} [Field F]
    (r : Fin 6 → F) (hd : Function.Injective r) (hn : ∀ i, r i ≠ 0)
    (base : FamilyCoins F) : Function.Bijective (maskedObservations r base) := by
  have h := familyMap_bijective r hd hn
  constructor
  · intro z w heq
    apply h.injective
    exact add_left_cancel heq
  · intro y
    obtain ⟨z, hz⟩ := h.surjective (y - base)
    refine ⟨z, ?_⟩
    simp [maskedObservations, hz]

/-- This is the algebraic masking endpoint; it does not assume a particular field size. -/
theorem masking_exists_unique {F : Type*} [Field F]
    (r : Fin 6 → F) (hd : Function.Injective r) (hn : ∀ i, r i ≠ 0)
    (base target : FamilyCoins F) : ∃! z, maskedObservations r base z = target := by
  obtain ⟨z, hz⟩ := (maskedObservations_bijective r hd hn base).surjective target
  refine ⟨z, hz, ?_⟩
  intro w hw
  exact (maskedObservations_bijective r hd hn base).injective (hw.trans hz.symm)

end HegemonCrypto.NativeHtlcPcs
