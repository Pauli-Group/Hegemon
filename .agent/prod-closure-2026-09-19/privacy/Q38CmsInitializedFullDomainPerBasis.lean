import Q38CmsInitializedFullDomainAggregationProbe

namespace HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaLeafFrameHybrid
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 20000
set_option exponentiation.threshold 1024
set_option linter.unusedSectionVars false

variable {Phase Work Branch Other : Type}
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Work] [DecidableEq Work]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype Other] [DecidableEq Other]

local notation "FullInput" => LeafInput ⊕ Other
local notation "FullCore" =>
  Core FullInput Branch (FullInput × Phase × Work) DigestRegister

/-- One fixed core basis supplies the collision estimate.  Extracting this
from the global finite sum prevents Lean from carrying the concrete FullCore
enumerator through the leaf-support proof. -/
theorem full_domain_per_basis_bound
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex) (core : FullCore → ℂ)
    (queries : Nat) (basis : FullCore)
    (supported : ∀ basis, core basis ≠ 0 →
      (recordedLeafInputs basis.2.1).card ≤ queries) :
    uniformAverage (fun tapes : LeafIndex → LeafTape =>
      if ∃ index ∈ indices,
        basis.2.1 (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
      then ‖core basis‖ ^ 2 else 0) ≤
      (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹ * ‖core basis‖ ^ 2 := by
  by_cases zero : core basis = 0
  · have zeroNorm : ‖core basis‖ ^ 2 = 0 := by
      simp only [zero, norm_zero, zero_pow (by decide : 2 ≠ 0)]
    rw [zeroNorm]
    simp only [ite_self, mul_zero]
    exact le_of_eq
      (uniform_average_const (A := LeafIndex → LeafTape) (0 : ℝ))
  · have pointwise (tapes : LeafIndex → LeafTape) :
        (if ∃ index ∈ indices,
            basis.2.1
              (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
          then ‖core basis‖ ^ 2 else 0) ≤
        (if leafIntersects (recordedLeafInputs basis.2.1)
            (sourcePatchSupport Finset.univ
              (fun _ => header (salt basis.1))
              (fun i => suffix (data basis.1 i)) tapes)
          then (1 : ℝ) else 0) * ‖core basis‖ ^ 2 := by
      by_cases hit : ∃ index ∈ indices,
          basis.2.1
            (fullPhysicalSelected salt data tapes basis.1 index) ≠ none
      · have selectedHit := hit
        obtain ⟨index, member, recorded⟩ := hit
        have overlaps : leafIntersects (recordedLeafInputs basis.2.1)
            (sourcePatchSupport Finset.univ
              (fun _ => header (salt basis.1))
              (fun i => suffix (data basis.1 i)) tapes) := by
          refine ⟨sourceLeafInput (header (salt basis.1))
            (suffix (data basis.1 index)) index (tapes index), ?_, ?_⟩
          · simpa only [recordedLeafInputs, Finset.mem_filter,
              Finset.mem_univ, true_and, fullPhysicalSelected] using recorded
          · exact Finset.mem_image.mpr ⟨index, Finset.mem_univ _, rfl⟩
        rw [if_pos selectedHit, if_pos overlaps, one_mul]
      · rw [if_neg hit]
        positivity
    apply (average_mono _ _ pointwise).trans
    rw [average_mul_right]
    apply mul_le_mul_of_nonneg_right _ (sq_nonneg _)
    exact (source_leaf_record_overlap (recordedLeafInputs basis.2.1)
      (salt basis.1) (data basis.1)).trans
        (mul_le_mul_of_nonneg_right
          (by exact_mod_cast supported basis zero) (by positivity))

end
end HegemonCrypto.SmallWood.Q38CmsInitializedResampling
