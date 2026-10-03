import HegemonCrypto.SmallWoodV8Smz9RankIncidence
import HegemonCrypto.SmallWoodV8Smz9DisjointCoset
import Mathlib.LinearAlgebra.Dual.Lemmas
import Mathlib.LinearAlgebra.Vandermonde
import Mathlib.FieldTheory.Finiteness

/-!
# Concrete linear algebra for rank-incidence supports

These lemmas bind distinct evaluation points and augmented data columns to the
rank-incidence count.  The high-rank tail allows the agreement set to depend on
the entire matrix.  Its span-dimension premise specifies the event being counted.
The exact current-coset specialization uses 388 code coordinates, 140 data
coordinates, and five independently sampled matrix rows.  Low-rank extraction,
verifier acceptance, Fiat--Shamir sampling, and production authority remain outside
these theorems.
-/

namespace HegemonCrypto.SmallWood.V8Smz9RankIncidenceBinding

open scoped BigOperators
open Module Submodule V8Smz9RankIncidence

noncomputable section

variable {F I V : Type*} [Field F] [AddCommGroup V] [Module F V]

/-- An independent vector family admits every assignment of scalar values by a
linear functional.  This follows from injectivity of its linear-combination map. -/
theorem independent_values_extend (v : I → V) (hv : LinearIndependent F v) (b : I → F) :
    ∃ f : Module.Dual F V, ∀ i, f (v i) = b i := by
  obtain ⟨f, hf⟩ := LinearMap.dualMap_surjective_of_injective
    hv.finsuppLinearCombination_injective (Finsupp.linearCombination F b)
  refine ⟨f, fun i => ?_⟩
  have hi := congrArg (fun g : Module.Dual F (I →₀ F) => g (Finsupp.single i 1)) hf
  simpa using hi

/-- The actual powers `1,x,...,x^(k-1)` on distinct points are independent. -/
theorem vandermonde_vectors_independent {k : ℕ} (x : Fin k → F)
    (hx : Function.Injective x) :
    LinearIndependent F (fun i : Fin k => fun j : Fin k => x i ^ j.val) := by
  exact Matrix.linearIndependent_rows_of_det_ne_zero
    (Matrix.det_vandermonde_ne_zero_iff.mpr hx)

/-- Appending arbitrary data coordinates preserves the Vandermonde independence. -/
theorem augmented_base_independent {k n : ℕ} (x : Fin k → F)
    (hx : Function.Injective x) (data : Fin k → Fin n → F) :
    LinearIndependent F (fun i => ((fun j : Fin k => x i ^ j.val), data i)) := by
  exact LinearIndependent.of_comp (LinearMap.fst F (Fin k → F) (Fin n → F))
    (vandermonde_vectors_independent x hx)

/-- Concrete matrix multiplication with independently chosen scalar coefficients. -/
def evaluationMap {n : ℕ} (v : I → Fin n → F) : (Fin n → F) →ₗ[F] (I → F) where
  toFun a i := ∑ j, a j * v i j
  map_add' a b := by ext i; simp [Finset.sum_add_distrib, add_mul]
  map_smul' c a := by ext i; simp [Finset.mul_sum, mul_assoc]

/-- Every linear functional on coordinate vectors has the concrete dot-product
representation used by the matrix sampler. -/
theorem functional_eq_coordinate_sum {n : ℕ} (f : Module.Dual F (Fin n → F))
    (x : Fin n → F) : f x = ∑ j, f (Pi.single j 1) * x j := by
  classical
  have hx : (∑ j, x j • Pi.single j (1 : F)) = x := by
    ext i
    simp [Pi.single_apply]
  calc
    f x = f (∑ j, x j • Pi.single j (1 : F)) := congrArg f hx.symm
    _ = ∑ j, f (Pi.single j 1) * x j := by
      rw [map_sum]
      apply Finset.sum_congr rfl
      intro j _
      simp [mul_comm]

/-- Independence of the actual augmented coordinate vectors makes the combined
code/data evaluation map surjective. -/
theorem augmented_evaluation_surjective {k n : ℕ}
    (codeVectors : I → Fin k → F) (dataVectors : I → Fin n → F)
    (haug : LinearIndependent F (fun i => (codeVectors i, dataVectors i))) :
    Function.Surjective ((evaluationMap codeVectors).coprod (evaluationMap dataVectors)) := by
  intro b
  obtain ⟨f, hf⟩ := independent_values_extend _ haug b
  let fc := f.comp (LinearMap.inl F (Fin k → F) (Fin n → F))
  let fd := f.comp (LinearMap.inr F (Fin k → F) (Fin n → F))
  refine ⟨(fun j => fc (Pi.single j 1), fun j => fd (Pi.single j 1)), ?_⟩
  ext i
  change (∑ j, fc (Pi.single j 1) * codeVectors i j) +
    (∑ j, fd (Pi.single j 1) * dataVectors i j) = b i
  rw [← functional_eq_coordinate_sum, ← functional_eq_coordinate_sum]
  change f (codeVectors i, 0) + f (0, dataVectors i) = b i
  rw [← map_add]
  simpa using hf i

/-- Restricted degree-less-than-`k` Reed--Solomon evaluation from coefficients. -/
def codeEvaluation {m : ℕ} (x : Fin m → F) (k : ℕ) :
    (Fin k → F) →ₗ[F] (Fin m → F) :=
  evaluationMap fun i j => x i ^ j.val

def restrictedCode {m : ℕ} (x : Fin m → F) (k : ℕ) : Submodule F (Fin m → F) :=
  LinearMap.range (codeEvaluation x k)

/-- On `k+r` distinct points, the restricted code has exactly `k` dimensions. -/
theorem codeEvaluation_injective {k r : ℕ} (x : Fin (k + r) → F)
    (hx : Function.Injective x) : Function.Injective (codeEvaluation x k) := by
  intro a b hab
  apply sub_eq_zero.mp
  apply Matrix.eq_zero_of_forall_index_sum_mul_pow_eq_zero
    (hx.comp (Fin.castAdd_injective k r))
  intro j
  have hz : codeEvaluation x k (a - b) = 0 := by rw [map_sub, hab, sub_self]
  exact congrFun hz (Fin.castAdd r j)

theorem restrictedCode_finrank {k r : ℕ} (x : Fin (k + r) → F)
    (hx : Function.Injective x) : finrank F (restrictedCode x k) = k := by
  exact (LinearMap.finrank_range_of_inj (codeEvaluation_injective x hx)).trans
    (Module.finrank_fin_fun F)

theorem restrictedCode_quotient_finrank {k r : ℕ} (x : Fin (k + r) → F)
    (hx : Function.Injective x) :
    finrank F ((Fin (k + r) → F) ⧸ restrictedCode x k) = r := by
  rw [Submodule.finrank_quotient, restrictedCode_finrank x hx, Module.finrank_fin_fun]
  exact Nat.add_sub_cancel_left k r

/-- The concrete challenge-to-residual map, quotienting out all degree-less-than-`k`
response polynomials on the fixed support. -/
def residualMap {k r n : ℕ} (x : Fin (k + r) → F)
    (data : Fin (k + r) → Fin n → F) :
    (Fin n → F) →ₗ[F] ((Fin (k + r) → F) ⧸ restrictedCode x k) :=
  (restrictedCode x k).mkQ.comp (evaluationMap data)

theorem residualMap_surjective {k r n : ℕ} (x : Fin (k + r) → F)
    (data : Fin (k + r) → Fin n → F)
    (haug : LinearIndependent F (fun i => ((fun j : Fin k => x i ^ j.val), data i))) :
    Function.Surjective (residualMap x data) := by
  exact quotient_data_map_surjective (codeEvaluation x k) (evaluationMap data)
    (augmented_evaluation_surjective _ _ haug)

/-- Exact quotient cardinality is derived from the restricted Vandermonde rank. -/
theorem restrictedCode_quotient_card {k r : ℕ} (x : Fin (k + r) → F)
    (hx : Function.Injective x) :
    Nat.card ((Fin (k + r) → F) ⧸ restrictedCode x k) = Nat.card F ^ r := by
  rw [Module.natCard_eq_pow_finrank (K := F), restrictedCode_quotient_finrank x hx]

/-- All masked matrix combinations fit degree-less-than-`k` responses on this
fixed support.  Both data and masks are fixed before matrix coefficients vary. -/
def FitsMaskedRows {k r n eta : ℕ} (x : Fin (k + r) → F)
    (data : Fin (k + r) → Fin n → F) (mask : Fin eta → Fin (k + r) → F)
    (a : Fin eta → Fin n → F) : Prop :=
  ∀ row, evaluationMap data (a row) + mask row ∈ restrictedCode x k

theorem fitsMaskedRows_iff_residual {k r n eta : ℕ} (x : Fin (k + r) → F)
    (data : Fin (k + r) → Fin n → F) (mask : Fin eta → Fin (k + r) → F)
    (a : Fin eta → Fin n → F) :
    FitsMaskedRows x data mask a ↔
      rowMap (residualMap x data) eta a = fun row => -(restrictedCode x k).mkQ (mask row) := by
  rw [funext_iff]
  apply forall_congr'
  intro row
  change evaluationMap data (a row) + mask row ∈ restrictedCode x k ↔
    (restrictedCode x k).mkQ (evaluationMap data (a row)) =
      -(restrictedCode x k).mkQ (mask row)
  rw [eq_neg_iff_add_eq_zero, ← map_add]
  exact (Submodule.Quotient.mk_eq_zero (restrictedCode x k)).symm

/-- Exact simultaneous support-fitting count for the full independent matrix.
The denominator `p^(r*eta)` is derived from augmented-vector independence and
distinct evaluation points, with no supplied fiber or probability premise. -/
theorem fixed_support_masked_rows_card [Fintype F] {k r n eta : ℕ}
    (x : Fin (k + r) → F) (hx : Function.Injective x)
    (data : Fin (k + r) → Fin n → F) (mask : Fin eta → Fin (k + r) → F)
    (haug : LinearIndependent F (fun i => ((fun j : Fin k => x i ^ j.val), data i))) :
    Nat.card {a : Fin eta → Fin n → F // FitsMaskedRows x data mask a} *
      Nat.card F ^ (r * eta) = Nat.card F ^ (n * eta) := by
  classical
  letI : Fintype ((Fin (k + r) → F) ⧸ restrictedCode x k) := Fintype.ofFinite _
  have h := affine_fiber_card_mul_target (rowMap (residualMap x data) eta)
    (rowMap_surjective _ (residualMap_surjective x data haug) eta)
    (fun row => -(restrictedCode x k).mkQ (mask row))
  let e : {a : Fin eta → Fin n → F // FitsMaskedRows x data mask a} ≃
      {a : Fin eta → Fin n → F // rowMap (residualMap x data) eta a =
        fun row => -(restrictedCode x k).mkQ (mask row)} :=
    Equiv.subtypeEquivRight (fitsMaskedRows_iff_residual x data mask)
  rw [← Nat.card_congr e] at h
  simpa only [Nat.card_fun, Nat.card_fin, restrictedCode_quotient_card x hx, ← pow_mul] using h

/-- The current certified Goldilocks coset gives independent 388-point bases,
including the actual arbitrary 140 data coordinates. -/
theorem smz9_augmented_base_independent
    (index : Fin 388 → Fin V8Smz9DisjointCoset.domainSize)
    (hindex : Function.Injective index)
    (data : Fin 388 → Fin 140 → Goldilocks) :
    LinearIndependent Goldilocks (fun i =>
      ((fun j : Fin 388 => V8Smz9DisjointCoset.evaluationPoint (index i) ^ j.val), data i)) := by
  exact augmented_base_independent _
    (V8Smz9DisjointCoset.evaluation_point_injective.comp hindex) data

/-- Exact five-row fixed-support count for the current degree-387, 140-data-row
geometry on the certified disjoint coset.  The independent augmented support
premise is the witness selected by the separate rank-incidence argument. -/
theorem smz9_fixed_support_masked_rows_card {r : ℕ}
    (index : Fin (388 + r) → Fin V8Smz9DisjointCoset.domainSize)
    (hindex : Function.Injective index)
    (data : Fin (388 + r) → Fin 140 → Goldilocks)
    (mask : Fin 5 → Fin (388 + r) → Goldilocks)
    (haug : LinearIndependent Goldilocks (fun i =>
      ((fun j : Fin 388 => V8Smz9DisjointCoset.evaluationPoint (index i) ^ j.val), data i))) :
    Nat.card {a : Fin 5 → Fin 140 → Goldilocks // FitsMaskedRows (k := 388) (r := r)
      (fun i => V8Smz9DisjointCoset.evaluationPoint (index i)) data mask a} *
      Nat.card Goldilocks ^ (r * 5) = Nat.card Goldilocks ^ 700 := by
  simpa only [Nat.reduceMul] using
    (fixed_support_masked_rows_card (k := 388) (r := r) (n := 140) (eta := 5)
      (fun i => V8Smz9DisjointCoset.evaluationPoint (index i))
      (V8Smz9DisjointCoset.evaluation_point_injective.comp hindex) data mask haug)

/-- Distinct points supply the base-independence premise on every finite
`k`-subset, not only on a pre-enumerated tuple. -/
theorem augmented_finset_base_independent {D : Type*} [Fintype D] {k n : ℕ}
    (x : D → F) (hx : Function.Injective x) (data : D → Fin n → F)
    (J : Finset D) (hJ : J.card = k) :
    LinearIndepOn F (fun i => ((fun j : Fin k => x i ^ j.val), data i)) (J : Set D) := by
  classical
  let e : (J : Set D) ≃ Fin k := Fintype.equivFinOfCardEq (by simpa using hJ)
  have he : Function.Injective (fun j : Fin k => x (e.symm j)) :=
    hx.comp (Subtype.val_injective.comp e.symm.injective)
  have hv := augmented_base_independent (fun j => x (e.symm j)) he
    (fun j => data (e.symm j))
  simpa only [LinearIndepOn, Function.comp_def, Equiv.symm_apply_apply] using
    hv.comp e e.injective

/-- Concrete Vandermonde/data columns satisfy the rank-incidence support count
for every agreement set having sufficient augmented span dimension. -/
theorem augmented_independent_support_count {D : Type*} [Fintype D] {k r n : ℕ}
    (x : D → F) (hx : Function.Injective x) (data : D → Fin n → F)
    (G : Finset D)
    (hrank : k + r ≤ finrank F (span F
      ((fun i => ((fun j : Fin k => x i ^ j.val), data i)) '' (G : Set D)))) :
    G.card.choose k ≤
      (independentSupports (F := F) (fun i => ((fun j : Fin k => x i ^ j.val), data i))
        G (k + r)).card * (k + r).choose k := by
  apply independent_support_count _ G k (k + r) (Nat.le_add_right k r) _ hrank
  intro J hJ
  exact augmented_finset_base_independent x hx data J (Finset.mem_powersetCard.mp hJ).2

/-- Support fitting written directly on a finite subset of the original domain. -/
def FitsOnSupport {D : Type*} {k n eta : ℕ} (x : D → F)
    (data : D → Fin n → F) (mask : Fin eta → D → F)
    (a : Fin eta → Fin n → F) (S : Finset D) : Prop :=
  ∀ row, ∃ c : Fin k → F, ∀ i ∈ S,
    (∑ j, c j * x i ^ j.val) = (∑ j, a row j * data i j) + mask row i

/-- Enumeration-free exact fixed-support count on the original finite domain. -/
theorem finset_fixed_support_card {D : Type*} [Fintype D] [Fintype F] {k r n eta : ℕ}
    (x : D → F) (hx : Function.Injective x) (data : D → Fin n → F)
    (mask : Fin eta → D → F) (S : Finset D) (hcard : S.card = k + r)
    (hind : LinearIndepOn F (fun i => ((fun j : Fin k => x i ^ j.val), data i))
      (S : Set D)) :
    Nat.card {a : Fin eta → Fin n → F // FitsOnSupport (k := k) x data mask a S} *
      Nat.card F ^ (r * eta) = Nat.card F ^ (n * eta) := by
  classical
  let e : (S : Set D) ≃ Fin (k + r) := Fintype.equivFinOfCardEq (by simpa using hcard)
  let xs : Fin (k + r) → F := fun i => x (e.symm i)
  let ds : Fin (k + r) → Fin n → F := fun i => data (e.symm i)
  let ms : Fin eta → Fin (k + r) → F := fun row i => mask row (e.symm i)
  have hinj : Function.Injective xs := hx.comp (Subtype.val_injective.comp e.symm.injective)
  have hinds : LinearIndependent F (fun i => ((fun j : Fin k => xs i ^ j.val), ds i)) :=
    hind.comp e.symm e.symm.injective
  have hfit (a : Fin eta → Fin n → F) :
      FitsOnSupport (k := k) x data mask a S ↔ FitsMaskedRows (k := k) (r := r) xs ds ms a := by
    constructor
    · intro h row
      obtain ⟨c, hc⟩ := h row
      refine ⟨c, funext fun i => ?_⟩
      exact hc (e.symm i).val (e.symm i).property
    · intro h row
      obtain ⟨c, hc⟩ := h row
      refine ⟨c, fun i hi => ?_⟩
      have heq := congrFun hc (e ⟨i, hi⟩)
      simpa [codeEvaluation, evaluationMap, xs, ds, ms] using heq
  have hcount := fixed_support_masked_rows_card (k := k) (r := r) xs hinj ds ms hinds
  rw [← Nat.card_congr (Equiv.subtypeEquivRight hfit)] at hcount
  exact hcount

/-- An arbitrary matrix-dependent agreement set may be chosen after seeing the
matrix.  Its high-rank, large-agreement event obeys the incidence bound.  The
premises specify agreement and rank, never a supplied probability estimate. -/
theorem adaptive_high_rank_count {D : Type*} [Fintype D] [Fintype F] {k r n eta : ℕ}
    (x : D → F) (hx : Function.Injective x) (data : D → Fin n → F)
    (mask : Fin eta → D → F) (threshold : ℕ)
    (B : Finset (Fin eta → Fin n → F))
    (G : (Fin eta → Fin n → F) → Finset D)
    (hsize : ∀ A ∈ B, threshold ≤ (G A).card)
    (hrank : ∀ A ∈ B, k + r ≤ finrank F (span F
      ((fun i => ((fun j : Fin k => x i ^ j.val), data i)) '' (G A : Set D))))
    (hfit : ∀ A ∈ B, FitsOnSupport (k := k) x data mask A (G A)) :
    B.card * threshold.choose k * Nat.card F ^ (r * eta) ≤
      (Fintype.card D).choose (k + r) * (k + r).choose k * Nat.card F ^ (n * eta) := by
  classical
  let v := fun i => ((fun j : Fin k => x i ^ j.val), data i)
  let U := independentSupports (F := F) v Finset.univ (k + r)
  let C := fun A => U.filter fun S => FitsOnSupport (k := k) x data mask A S
  have hlow : ∀ A ∈ B, threshold.choose k ≤ (C A).card * (k + r).choose k := by
    intro A hA
    have hsub : independentSupports (F := F) v (G A) (k + r) ⊆ C A := by
      intro S hS
      obtain ⟨hScard, hSind⟩ := Finset.mem_filter.mp hS
      obtain ⟨hSG, hScard⟩ := Finset.mem_powersetCard.mp hScard
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_filter.mpr
        ⟨Finset.mem_powersetCard.mpr ⟨Finset.subset_univ S, hScard⟩, hSind⟩, ?_⟩
      intro row
      obtain ⟨c, hc⟩ := hfit A hA row
      exact ⟨c, fun i hi => hc i (hSG hi)⟩
    calc
      threshold.choose k ≤ (G A).card.choose k := Nat.choose_le_choose k (hsize A hA)
      _ ≤ (independentSupports (F := F) v (G A) (k + r)).card * (k + r).choose k :=
        augmented_independent_support_count x hx data (G A) (hrank A hA)
      _ ≤ (C A).card * (k + r).choose k :=
        Nat.mul_le_mul_right _ (Finset.card_le_card hsub)
  have hsum : (∑ A : Fin eta → Fin n → F, (C A).card) * Nat.card F ^ (r * eta) =
      U.card * Nat.card F ^ (n * eta) := by
    have hswap : (∑ A : Fin eta → Fin n → F, (C A).card) =
        ∑ S ∈ U, Nat.card {A : Fin eta → Fin n → F // FitsOnSupport (k := k) x data mask A S} := by
      simp only [C, Nat.card_eq_fintype_card, Fintype.card_subtype,
        Finset.card_eq_sum_ones, Finset.sum_filter]
      exact Finset.sum_comm
    rw [hswap, Finset.sum_mul]
    calc
      _ = ∑ _S ∈ U, Nat.card F ^ (n * eta) := by
        apply Finset.sum_congr rfl
        intro S hS
        obtain ⟨hScard, hSind⟩ := Finset.mem_filter.mp hS
        exact finset_fixed_support_card x hx data mask S
          (Finset.mem_powersetCard.mp hScard).2 hSind
      _ = _ := by simp
  have hU : U.card ≤ (Fintype.card D).choose (k + r) := by
    calc
      U.card ≤ (Finset.univ.powersetCard (k + r) : Finset (Finset D)).card :=
        Finset.card_filter_le _ _
      _ = _ := by simp
  calc
    B.card * threshold.choose k * Nat.card F ^ (r * eta) =
        (∑ _A ∈ B, threshold.choose k) * Nat.card F ^ (r * eta) := by simp
    _ ≤ (∑ A ∈ B, (C A).card * (k + r).choose k) * Nat.card F ^ (r * eta) :=
      Nat.mul_le_mul_right _ (Finset.sum_le_sum hlow)
    _ ≤ (∑ A : Fin eta → Fin n → F, (C A).card * (k + r).choose k) *
        Nat.card F ^ (r * eta) :=
      Nat.mul_le_mul_right _ (Finset.sum_le_sum_of_subset (Finset.subset_univ B))
    _ = ((∑ A : Fin eta → Fin n → F, (C A).card) * Nat.card F ^ (r * eta)) *
        (k + r).choose k := by rw [← Finset.sum_mul]; ac_rfl
    _ = U.card * (k + r).choose k * Nat.card F ^ (n * eta) := by rw [hsum]; ac_rfl
    _ ≤ _ := Nat.mul_le_mul_right _ (Nat.mul_le_mul_right _ hU)

/-- Current-coset high-rank tail, in integer form to avoid silently dividing by
a zero binomial coefficient.  For `threshold ≥ 388`, division by the matrix
space size and left-hand weight gives the corresponding uniform probability
bound.  Agreement sets may depend arbitrarily on the sampled matrix. -/
theorem smz9_adaptive_high_rank_count {r : ℕ}
    (data : Fin V8Smz9DisjointCoset.domainSize → Fin 140 → Goldilocks)
    (mask : Fin 5 → Fin V8Smz9DisjointCoset.domainSize → Goldilocks)
    (threshold : ℕ) (B : Finset (Fin 5 → Fin 140 → Goldilocks))
    (G : (Fin 5 → Fin 140 → Goldilocks) → Finset (Fin V8Smz9DisjointCoset.domainSize))
    (hsize : ∀ A ∈ B, threshold ≤ (G A).card)
    (hrank : ∀ A ∈ B, 388 + r ≤ finrank Goldilocks (span Goldilocks
      ((fun i => ((fun j : Fin 388 => V8Smz9DisjointCoset.evaluationPoint i ^ j.val),
        data i)) '' (G A : Set (Fin V8Smz9DisjointCoset.domainSize)))))
    (hfit : ∀ A ∈ B, FitsOnSupport (k := 388) V8Smz9DisjointCoset.evaluationPoint
      data mask A (G A)) :
    B.card * threshold.choose 388 * Nat.card Goldilocks ^ (r * 5) ≤
      V8Smz9DisjointCoset.domainSize.choose (388 + r) * (388 + r).choose 388 *
        Nat.card Goldilocks ^ 700 := by
  simpa only [Fintype.card_fin, Nat.reduceMul] using
    (adaptive_high_rank_count (k := 388) (r := r) (n := 140) (eta := 5)
      V8Smz9DisjointCoset.evaluationPoint V8Smz9DisjointCoset.evaluation_point_injective
      data mask threshold B G hsize hrank hfit)

end

end HegemonCrypto.SmallWood.V8Smz9RankIncidenceBinding
