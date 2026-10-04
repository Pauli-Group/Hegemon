import Mca38NestedFactorSeparability
import Mca38NestedContentExceptions
import Mca38NestedInterpolationHeights
import Mca38EliminationDegree

/-! A single base-field X-coordinate for the actual nested factor family.
The obstruction stays in K[Z][X]. We never evaluate the rational-function
field at a base-field Z value, and never assume a common regular point.
-/
namespace HegemonCrypto.SmallWood.Mca38NestedRegularPoint
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open HegemonCrypto.SmallWood.Mca38NestedFactorSeparability
open HegemonCrypto.SmallWood.Mca38NestedContentExceptions (coefficient_degree_le_swap)
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false

section Heights
variable {R : Type*} [CommRing R]

theorem resultant_height (f g : Polynomial (Polynomial R)) (D m n : Nat)
    (hf : ∀ j, (f.coeff j).natDegree ≤ D)
    (hg : ∀ j, (g.coeff j).natDegree ≤ D) :
    (f.resultant g m n).natDegree ≤ (m + n) * D := by
  have entries : ∀ i j, ((Polynomial.sylvester f g m n) i j).natDegree ≤ D := by
    intro i j
    refine Fin.addCases (fun j => ?_) (fun j => ?_) j
    · simp only [Polynomial.sylvester, Matrix.of_apply, Fin.addCases_left]
      split_ifs
      · exact hg _
      · simp
    · simp only [Polynomial.sylvester, Matrix.of_apply, Fin.addCases_right]
      split_ifs
      · exact hf _
      · simp
  simpa [Polynomial.resultant] using
    HegemonCrypto.SmallWood.Mca38Published.elimination_determinant_natDegree
      (Polynomial.sylvester f g m n) (fun _ => D) entries

theorem regularity_height (f : Polynomial (Polynomial R)) (D : Nat)
    (positive : 0 < f.natDegree) (hf : ∀ j, (f.coeff j).natDegree ≤ D) :
    (f.leadingCoeff * f.resultant f.derivative).natDegree ≤ 2 * f.natDegree * D := by
  have derivativeHeight : ∀ j, (f.derivative.coeff j).natDegree ≤ D := by
    intro j
    rw [Polynomial.coeff_derivative]
    rw [show (j : Polynomial R) + 1 = Polynomial.C ((j : R) + 1) by simp]
    exact Polynomial.natDegree_mul_le.trans
      (by simpa only [Polynomial.natDegree_C, add_zero] using hf (j + 1))
  have resultantHeight := resultant_height f f.derivative D
    f.natDegree f.derivative.natDegree hf derivativeHeight
  have derivativeDegree := Polynomial.natDegree_derivative_le f
  calc
    _ ≤ f.leadingCoeff.natDegree + (f.resultant f.derivative).natDegree :=
      Polynomial.natDegree_mul_le
    _ ≤ D + (f.natDegree + f.derivative.natDegree) * D :=
      Nat.add_le_add (hf f.natDegree) resultantHeight
    _ = (f.natDegree + f.derivative.natDegree + 1) * D := by ring
    _ ≤ 2 * f.natDegree * D := Nat.mul_le_mul_right D (by omega)

end Heights

variable {K : Type*} [Field K]

theorem regularity_X_degree (H : Tri (K := K)) (positive : 0 < H.natDegree) :
    (regularityObstruction H).natDegree ≤ 2 * H.natDegree * (xView H).natDegree := by
  exact regularity_height H (xView H).natDegree positive
    (fun j => coefficient_degree_le_swap H j)

theorem regularity_swap (H : Tri (K := K)) :
    Polynomial.Bivariate.swap (regularityObstruction H) =
      regularityObstruction
        (H.map (Polynomial.Bivariate.swap (R := K)).toRingHom) := by
  let σ : Polynomial (Polynomial K) →+* Polynomial (Polynomial K) :=
    (Polynomial.Bivariate.swap (R := K)).toRingHom
  have injective : Function.Injective σ := (Polynomial.Bivariate.swap (R := K)).injective
  change σ (regularityObstruction H) = regularityObstruction (H.map σ)
  simp only [regularityObstruction,
    Polynomial.leadingCoeff_map_of_injective (f := σ) injective,
    Polynomial.derivative_map,
    Polynomial.natDegree_map_eq_of_injective (f := σ) injective,
    map_mul]
  rw [Polynomial.derivative_map, Polynomial.resultant_map_map]

theorem regularity_Z_degree (H : Tri (K := K)) (positive : 0 < H.natDegree) :
    (Polynomial.Bivariate.swap (regularityObstruction H)).natDegree ≤
      2 * H.natDegree * (zView H).natDegree := by
  rw [regularity_swap]
  have mappedDegree := Polynomial.natDegree_map_eq_of_injective
    (f := (Polynomial.Bivariate.swap (R := K)).toRingHom)
    (Polynomial.Bivariate.swap (R := K)).injective H
  have mappedPositive : 0 <
      (H.map (Polynomial.Bivariate.swap (R := K)).toRingHom).natDegree := by
    rwa [mappedDegree]
  have bound := regularity_X_degree
    (H.map (Polynomial.Bivariate.swap (R := K)).toRingHom) mappedPositive
  simpa only [mappedDegree, xView, zView, RingHom.comp_apply,
    Polynomial.coe_mapRingHom, RingHom.coe_coe] using bound

theorem eval_constant_eq_map_swap (P : Polynomial (Polynomial K)) (x : K) :
    P.eval (Polynomial.C x) =
      (Polynomial.Bivariate.swap P).map (Polynomial.evalRingHom x) := by
  have eval_C_id : (Polynomial.evalRingHom x).comp Polynomial.C = RingHom.id K := by
    ext a
    simp
  induction P using Polynomial.induction_on' with
  | add p q hp hq => simp only [Polynomial.eval_add, map_add, Polynomial.map_add, hp, hq]
  | monomial n p =>
    simp [Polynomial.Bivariate.swap_monomial, Polynomial.eval_monomial,
      Polynomial.map_map, Polynomial.map_mul, Polynomial.map_pow, eval_C_id]

/-- A nonzero polynomial in K[Z][X] cannot vanish identically in Z at more
base-field X values than its actual X degree. -/
theorem exists_nonzero_base_specialization (P : Polynomial (Polynomial K))
    (nonzero : P ≠ 0) (candidates : Finset K) (large : P.natDegree < candidates.card) :
    ∃ x ∈ candidates, P.eval (Polynomial.C x) ≠ 0 := by
  have swappedNonzero : Polynomial.Bivariate.swap P ≠ 0 := by
    intro zero
    apply nonzero
    exact (Polynomial.Bivariate.swap (R := K)).injective
      (zero.trans (map_zero _).symm)
  obtain ⟨j, coefficient⟩ : ∃ j, (Polynomial.Bivariate.swap P).coeff j ≠ 0 := by
    by_contra! allZero
    exact swappedNonzero (Polynomial.ext (by simpa using allZero))
  have degree : ((Polynomial.Bivariate.swap P).coeff j).natDegree ≤ P.natDegree := by
    have swapped := coefficient_degree_le_swap (Polynomial.Bivariate.swap P) j
    have involution : Polynomial.Bivariate.swap (Polynomial.Bivariate.swap P) = P := by
      exact Polynomial.Bivariate.swap_swap_apply P
    rwa [involution] at swapped
  by_contra! allZero
  have count : candidates.card ≤ ((Polynomial.Bivariate.swap P).coeff j).natDegree := by
    apply Polynomial.card_le_degree_of_subset_roots
    intro x member
    apply (Polynomial.mem_roots coefficient).mpr
    have zero := allZero x member
    rw [eval_constant_eq_map_swap] at zero
    have coeffZero := congrArg (fun p : Polynomial K => p.coeff j) zero
    change ((Polynomial.Bivariate.swap P).coeff j).eval x = 0
    simpa only [Polynomial.coeff_map, Polynomial.coeff_zero,
      Polynomial.coe_evalRingHom] using coeffZero
  exact (Nat.not_lt_of_ge (count.trans degree)) large

def factorObstruction (H : Tri (K := K)) : Polynomial (Polynomial K) :=
  if 0 < H.natDegree then regularityObstruction H else 1

def globalObstruction (F : Tri (K := K)) : Polynomial (Polynomial K) :=
  ((factors F).map factorObstruction).prod

theorem factorObstruction_X_degree (H : Tri (K := K)) :
    (factorObstruction H).natDegree ≤ 2 * H.natDegree * (xView H).natDegree := by
  unfold factorObstruction
  split_ifs with positive
  · exact regularity_X_degree H positive
  · simp

theorem obstruction_product_X_degree (fs : Multiset (Tri (K := K))) (Y : Nat)
    (degrees : ∀ H ∈ fs, H.natDegree ≤ Y) :
    ((fs.map factorObstruction).prod).natDegree ≤
      2 * Y * (fs.map (fun H => (xView H).natDegree)).sum := by
  induction fs using Multiset.induction_on with
  | empty => simp
  | cons H fs ih =>
    simp only [Multiset.map_cons, Multiset.prod_cons, Multiset.sum_cons]
    have head := (factorObstruction_X_degree H).trans
      (Nat.mul_le_mul_right (xView H).natDegree
        (Nat.mul_le_mul_left 2 (degrees H (Multiset.mem_cons_self H fs))))
    have tail := ih (fun G member => degrees G (Multiset.mem_cons_of_mem member))
    exact Polynomial.natDegree_mul_le.trans
      ((Nat.add_le_add head tail).trans (by rw [Nat.mul_add]))

theorem globalObstruction_X_degree (F : Tri (K := K)) (hF : F ≠ 0) :
    (globalObstruction F).natDegree ≤ 2 * F.natDegree * (xView F).natDegree := by
  have bound := obstruction_product_X_degree (factors F) F.natDegree
    (fun _ member => actual_factor_degree_le hF member)
  rwa [(degree_ledger F hF).2.1] at bound

theorem factorObstruction_Z_degree (H : Tri (K := K)) :
    (Polynomial.Bivariate.swap (factorObstruction H)).natDegree ≤
      2 * H.natDegree * (zView H).natDegree := by
  unfold factorObstruction
  split_ifs with positive
  · exact regularity_Z_degree H positive
  · simp

theorem obstruction_product_Z_degree (fs : Multiset (Tri (K := K))) (Y : Nat)
    (degrees : ∀ H ∈ fs, H.natDegree ≤ Y) :
    (Polynomial.Bivariate.swap ((fs.map factorObstruction).prod)).natDegree ≤
      2 * Y * (fs.map (fun H => (zView H).natDegree)).sum := by
  induction fs using Multiset.induction_on with
  | empty => simp
  | cons H fs ih =>
    simp only [Multiset.map_cons, Multiset.prod_cons, Multiset.sum_cons, map_mul]
    have head := (factorObstruction_Z_degree H).trans
      (Nat.mul_le_mul_right (zView H).natDegree
        (Nat.mul_le_mul_left 2 (degrees H (Multiset.mem_cons_self H fs))))
    have tail := ih (fun G member => degrees G (Multiset.mem_cons_of_mem member))
    exact Polynomial.natDegree_mul_le.trans
      ((Nat.add_le_add head tail).trans (by rw [Nat.mul_add]))

theorem globalObstruction_Z_degree (F : Tri (K := K)) (hF : F ≠ 0) :
    (Polynomial.Bivariate.swap (globalObstruction F)).natDegree ≤
      2 * F.natDegree * (zView F).natDegree := by
  have bound := obstruction_product_Z_degree (factors F) F.natDegree
    (fun _ member => actual_factor_degree_le hF member)
  rwa [(degree_ledger F hF).2.2] at bound

theorem globalObstruction_ne_zero (F : Tri (K := K)) (hF : F ≠ 0)
    (small : F.natDegree < ringChar (Rat K)) : globalObstruction F ≠ 0 := by
  apply Multiset.prod_ne_zero
  intro member
  obtain ⟨H, factor, zero⟩ := Multiset.mem_map.mp member
  have nonzero : factorObstruction H ≠ 0 := by
    unfold factorObstruction
    split_ifs with positive
    · exact actual_positive_factor_obstruction_ne_zero hF factor positive small
    · exact one_ne_zero
  exact nonzero zero

/-- The common coordinate is constructed from the actual finite factor
product. Only a numerical candidate-cardinality comparison remains to be
specialized; no regularity or root assignment is supplied as a premise. -/
theorem actual_common_regular_coordinate (F : Tri (K := K)) (hF : F ≠ 0)
    (small : F.natDegree < ringChar (Rat K)) (candidates : Finset K)
    (large : (globalObstruction F).natDegree < candidates.card) :
    ∃ x ∈ candidates, ∀ H ∈ factors F, 0 < H.natDegree →
      (regularityObstruction H).eval (Polynomial.C x) ≠ 0 := by
  obtain ⟨x, member, nonzero⟩ := exists_nonzero_base_specialization
    (globalObstruction F) (globalObstruction_ne_zero F hF small) candidates large
  refine ⟨x, member, ?_⟩
  intro H factor positive zero
  have divides : factorObstruction H ∣ globalObstruction F :=
    Multiset.dvd_prod (Multiset.mem_map.mpr ⟨H, factor, rfl⟩)
  obtain ⟨q, identity⟩ := divides
  apply nonzero
  rw [identity, Polynomial.eval_mul]
  simp only [factorObstruction, if_pos positive, zero, zero_mul]

/-- The q38 source supplies the numerical common-start budget internally.
The 530,841,600 bound is analysis only and changes no proof bytes. -/
theorem rbr_common_regular_coordinate
    (c : HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation.CoefficientIndex → K)
    (nonzero : c ≠ 0)
    (small : 810 < ringChar (Rat K)) (candidates : Finset K)
    (large : 530841600 < candidates.card) :
    ∃ x ∈ candidates, ∀ H ∈ factors
      (HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested c),
      0 < H.natDegree → (regularityObstruction H).eval (Polynomial.C x) ≠ 0 := by
  let F := HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested c
  have hF : F ≠ 0 := HegemonCrypto.SmallWood.Mca38RoundByRound.trivariateNested_ne_zero c nonzero
  have heights :=
    HegemonCrypto.SmallWood.Mca38NestedInterpolationHeights.actual_nested_interpolant_heights c
  have y : F.natDegree ≤ 810 := heights.1
  have x : (xView F).natDegree ≤ 327680 := heights.2.1
  apply actual_common_regular_coordinate F hF (y.trans_lt small) candidates
  apply (globalObstruction_X_degree F hF).trans_lt
  have budget : 2 * F.natDegree * (xView F).natDegree ≤ 530841600 := by
    calc
      _ ≤ 2 * 810 * 327680 := Nat.mul_le_mul (Nat.mul_le_mul_left 2 y) x
      _ = 530841600 := by norm_num
  exact budget.trans_lt large

def singularLabels (F : Tri (K := K)) (x : K) (labels : Finset K) : Finset K :=
  labels.filter fun z => ((globalObstruction F).eval (Polynomial.C x)).eval z = 0

theorem singularLabels_card_le (F : Tri (K := K)) (hF : F ≠ 0)
    (x : K) (regular : (globalObstruction F).eval (Polynomial.C x) ≠ 0)
    (labels : Finset K) :
    (singularLabels F x labels).card ≤ 2 * F.natDegree * (zView F).natDegree := by
  have count : (singularLabels F x labels).card ≤
      ((globalObstruction F).eval (Polynomial.C x)).natDegree := by
    apply Polynomial.card_le_degree_of_subset_roots
    intro z member
    exact (Polynomial.mem_roots regular).mpr (Finset.mem_filter.mp member).2
  apply count.trans
  rw [eval_constant_eq_map_swap]
  exact Polynomial.natDegree_map_le.trans (globalObstruction_Z_degree F hF)

theorem factor_regular_outside_singularLabels (F : Tri (K := K)) (x z : K)
    (labels : Finset K) (member : z ∈ labels)
    (outside : z ∉ singularLabels F x labels)
    (H : Tri (K := K)) (factor : H ∈ factors F) (positive : 0 < H.natDegree) :
    ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0 := by
  intro zero
  apply outside
  apply Finset.mem_filter.mpr
  refine ⟨member, ?_⟩
  have divides : factorObstruction H ∣ globalObstruction F :=
    Multiset.dvd_prod (Multiset.mem_map.mpr ⟨H, factor, rfl⟩)
  obtain ⟨q, identity⟩ := divides
  rw [identity, Polynomial.eval_mul, Polynomial.eval_mul]
  simp only [factorObstruction, if_pos positive, zero, zero_mul]

end
end HegemonCrypto.SmallWood.Mca38NestedRegularPoint
