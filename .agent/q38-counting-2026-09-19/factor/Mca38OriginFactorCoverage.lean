import Mca38PrimitiveFactorDegreeBudget

/-! Actual primitive origin factors, including specialized-root coverage.
The content is not silently discarded: nonvanishing of the specialized
leading coefficient proves that it cannot absorb the specialized root.
-/
namespace HegemonCrypto.SmallWood.Mca38OriginFactorCoverage
open HegemonCrypto.SmallWood.Mca38Published
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
variable {K : Type*} [Field K]

theorem content_eval_ne_zero (F : Polynomial (Polynomial K)) (z : K)
    (leading : F.leadingCoeff.eval z ≠ 0) : F.content.eval z ≠ 0 := by
  intro zero
  obtain ⟨q, product⟩ := Polynomial.content_dvd_coeff (p := F) F.natDegree
  apply leading
  change (F.coeff F.natDegree).eval z = 0
  rw [product, Polynomial.eval_mul, zero, zero_mul]

theorem primitive_product_root_coverage
    (F : Polynomial (Polynomial K))
    (fs : Multiset (Polynomial (Polynomial K)))
    (associated : Associated (Polynomial.C F.content * fs.prod) F)
    (z t : K) (leading : F.leadingCoeff.eval z ≠ 0)
    (root : F.eval₂ (Polynomial.evalRingHom z) t = 0) :
    ∃ G ∈ fs, G.eval₂ (Polynomial.evalRingHom z) t = 0 := by
  let φ : Polynomial (Polynomial K) →+* K :=
    Polynomial.eval₂RingHom (Polynomial.evalRingHom z) t
  have mapped := associated.map φ
  have productZero : φ (Polynomial.C F.content * fs.prod) = 0 :=
    mapped.eq_zero_iff.mpr root
  rw [map_mul] at productZero
  have contentNonzero : φ (Polynomial.C F.content) ≠ 0 := by
    simpa only [φ, Polynomial.coe_eval₂RingHom, Polynomial.eval₂_C,
      Polynomial.coe_evalRingHom] using content_eval_ne_zero F z leading
  have remainingZero : φ fs.prod = 0 :=
    (mul_eq_zero.mp productZero).resolve_left contentNonzero
  have mappedZero : (fs.map φ).prod = 0 := by
    simpa only [map_multiset_prod] using remainingZero
  by_contra absent
  push Not at absent
  have nonzero : (fs.map φ).prod ≠ 0 := by
    apply Multiset.prod_ne_zero
    intro member
    obtain ⟨G, factor, zero⟩ := Multiset.mem_map.mp member
    exact absent G factor zero
  exact nonzero mappedZero

/-- A genuine finite family, with degree budgets, fraction-field
irreducibility, divisibility, and simultaneous coverage of every specialized
root. No supplied family, root assignment, or exceptional count is assumed. -/
theorem exists_primitive_origin_family (F : Polynomial (Polynomial K)) (hF : F ≠ 0) :
    ∃ fs : Multiset (Polynomial (Polynomial K)),
      (∀ G ∈ fs, Irreducible G ∧ G.IsPrimitive ∧
        Irreducible (G.map (algebraMap (Polynomial K) (FractionRing (Polynomial K)))) ∧
        0 < G.natDegree ∧ G ∣ F) ∧
      (fs.map Polynomial.natDegree).sum = F.natDegree ∧
      (fs.map bivariateCoefficientHeight).sum ≤ bivariateCoefficientHeight F ∧
      ∀ z t : K, F.leadingCoeff.eval z ≠ 0 →
        F.eval₂ (Polynomial.evalRingHom z) t = 0 →
          ∃ G ∈ fs, G.eval₂ (Polynomial.evalRingHom z) t = 0 := by
  obtain ⟨fs, associated, irreducible, degreeY, degreeZ, contentProduct⟩ :=
    actual_primitive_factor_degree_budget F hF
  refine ⟨fs, ?_, degreeY, degreeZ, ?_⟩
  · intro G member
    obtain ⟨irr, primitive, mapped, positive⟩ := irreducible G member
    exact ⟨irr, primitive, mapped, positive,
      (Multiset.dvd_prod member).trans (associated.dvd.trans F.primPart_dvd)⟩
  · intro z t leading root
    exact primitive_product_root_coverage F fs contentProduct z t leading root

end
end HegemonCrypto.SmallWood.Mca38OriginFactorCoverage
