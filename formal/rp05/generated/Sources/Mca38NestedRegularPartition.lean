import Mca38NestedRegularPoint
import Mca38NestedIndependentUnion

/-! The actual first two branches of the global q38 label partition.
Both exceptional sets are constructed from the one Hasse interpolant. Outside
their union every specialized response belongs to an actual positive-Y factor
with a nonvanishing leading-coefficient/derivative-resultant obstruction.
-/
namespace HegemonCrypto.SmallWood.Mca38NestedRegularPartition
open HegemonCrypto.SmallWood.Mca38NestedFactorCoverage
open HegemonCrypto.SmallWood.Mca38NestedFactorSeparability
open HegemonCrypto.SmallWood.Mca38NestedInterpolationHeights
open HegemonCrypto.SmallWood.Mca38NestedIndependentUnion
open HegemonCrypto.SmallWood.Mca38NestedRegularPoint
open HegemonCrypto.SmallWood.Mca38RoundByRound
open HegemonCrypto.SmallWood.Mca38RoundByRoundInterpolation
open scoped Classical
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

def badStartLabels (F : Tri (K := K)) (x : K) (labels : Finset K) : Finset K :=
  independentLabels (factors F) labels ∪ singularLabels F x labels

theorem rbr_obstruction_degrees (c : CoefficientIndex → K) (hc : c ≠ 0) :
    (globalObstruction (trivariateNested c)).natDegree ≤ 530841600 ∧
    2 * (trivariateNested c).natDegree * (zView (trivariateNested c)).natDegree ≤ 16200000 := by
  have heights := actual_nested_interpolant_heights c
  have y : (trivariateNested c).natDegree ≤ 810 := heights.1
  have x : (xView (trivariateNested c)).natDegree ≤ 327680 := heights.2.1
  have z : (zView (trivariateNested c)).natDegree ≤ 10000 := heights.2.2
  constructor
  · apply (globalObstruction_X_degree _ (trivariateNested_ne_zero c hc)).trans
    calc
      _ ≤ 2 * 810 * 327680 := Nat.mul_le_mul (Nat.mul_le_mul_left 2 y) x
      _ = 530841600 := by norm_num
  · calc
      _ ≤ 2 * 810 * 10000 := Nat.mul_le_mul (Nat.mul_le_mul_left 2 y) z
      _ = 16200000 := by norm_num

theorem rbr_regular_start_partition (c : CoefficientIndex → K) (hc : c ≠ 0)
    (small : 810 < ringChar (Rat K)) (candidates labels : Finset K)
    (large : 530841600 < candidates.card) :
    ∃ x ∈ candidates,
      (badStartLabels (trivariateNested c) x labels).card ≤ 16210000 ∧
      ∀ z ∈ labels, z ∉ badStartLabels (trivariateNested c) x labels →
        ∀ P : Polynomial K, specializePoly z P (trivariateNested c) = 0 →
          ∃ H ∈ factors (trivariateNested c), 0 < H.natDegree ∧
            specializePoly z P H = 0 ∧
            ((regularityObstruction H).eval (Polynomial.C x)).eval z ≠ 0 := by
  let F := trivariateNested c
  have hF : F ≠ 0 := trivariateNested_ne_zero c hc
  have y : F.natDegree ≤ 810 := (actual_nested_interpolant_heights c).1
  have degrees := rbr_obstruction_degrees c hc
  obtain ⟨x, member, regular⟩ := exists_nonzero_base_specialization
    (globalObstruction F) (globalObstruction_ne_zero F hF (y.trans_lt small))
    candidates (degrees.1.trans_lt large)
  refine ⟨x, member, ?_, ?_⟩
  · calc
      _ ≤ (independentLabels (factors F) labels).card +
          (singularLabels F x labels).card := Finset.card_union_le _ _
      _ ≤ 16210000 := by
        have independent := rbr_independent_labels_card_le c hc labels
        have singular := (singularLabels_card_le F hF x regular labels).trans degrees.2
        exact (Nat.add_le_add independent singular).trans (by norm_num)
  · intro z hz outside P root
    have exclusions := Finset.notMem_union.mp outside
    obtain ⟨H, factor, positive, factorRoot⟩ :=
      positive_factor_outside_independent_labels F hF labels z hz exclusions.1 P root
    exact ⟨H, factor, positive, factorRoot,
      factor_regular_outside_singularLabels F x z labels hz exclusions.2 H factor positive⟩

end
end HegemonCrypto.SmallWood.Mca38NestedRegularPartition
