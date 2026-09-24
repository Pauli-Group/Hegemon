import Q38CmsInitializedFullDomainImportProbe

namespace HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainAggregationProbe
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 20000

theorem four_mul_finite_sum_mono
    {A : Type} [Fintype A] (left right : A → ℝ)
    (bound : ∀ index, left index ≤ right index) :
    4 * ∑ index, left index ≤ 4 * ∑ index, right index := by
  exact mul_le_mul_of_nonneg_left
    (Finset.sum_le_sum fun index _ => bound index) (by norm_num)

theorem four_mul_sum_product_factor
    {A : Type} [Fintype A] (query scale : ℝ) (mass : A → ℝ) :
    4 * ∑ index, query * scale * mass index =
      4 * query * scale * ∑ index, mass index := by
  rw [← Finset.mul_sum]
  ring

theorem average_four_mul_sum_product_bound
    {Secret A : Type} [Fintype Secret] [Nonempty Secret] [Fintype A]
    (query scale : ℝ) (mass : A → ℝ) (value : Secret → A → ℝ)
    (bound : ∀ index,
      uniformAverage (fun secret => value secret index) ≤
        query * scale * mass index) :
    uniformAverage (fun secret => 4 * ∑ index, value secret index) ≤
      4 * query * scale * ∑ index, mass index := by
  rw [average_mul_left, average_sum]
  exact (four_mul_finite_sum_mono
    (fun index => uniformAverage (fun secret => value secret index))
    (fun index => query * scale * mass index) bound).trans_eq
      (four_mul_sum_product_factor query scale mass)

end
end HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainAggregationProbe
