import Q38CmsInitializedFullDomainAggregationProbe

namespace HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainAggregationInterface
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

/-- Finset-indexed aggregation proved without any concrete CMS basis.  The
caller supplies the exact finite domain, so no second `Fintype` dictionary is
synthesized when this theorem is specialized. -/
theorem average_four_mul_finset_product_bound
    {Secret A : Type} [Fintype Secret] [Nonempty Secret]
    (domain : Finset A) (query scale : ℝ)
    (mass : A → ℝ) (value : Secret → A → ℝ)
    (bound : ∀ index ∈ domain,
      uniformAverage (fun secret => value secret index) ≤
        query * scale * mass index) :
    uniformAverage (fun secret =>
      4 * ∑ index ∈ domain, value secret index) ≤
      4 * query * scale * ∑ index ∈ domain, mass index := by
  rw [average_mul_left]
  have commute :
      uniformAverage (fun secret => ∑ index ∈ domain, value secret index) =
        ∑ index ∈ domain,
          uniformAverage (fun secret => value secret index) := by
    unfold uniformAverage
    simp only [Finset.mul_sum]
    rw [Finset.sum_comm]
  rw [commute]
  calc
    4 * ∑ index ∈ domain,
        uniformAverage (fun secret => value secret index) ≤
      4 * ∑ index ∈ domain, query * scale * mass index := by
        apply mul_le_mul_of_nonneg_left _ (by norm_num)
        exact Finset.sum_le_sum fun index member => bound index member
    _ = 4 * query * scale * ∑ index ∈ domain, mass index := by
      rw [← Finset.mul_sum]
      ring

end
end HegemonCrypto.SmallWood.Q38CmsInitializedFullDomainAggregationInterface
