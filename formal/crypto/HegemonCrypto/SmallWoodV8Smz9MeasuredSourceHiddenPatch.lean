import HegemonCrypto.SmallWoodV8Smz9MeasuredOracleHybrid

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredSourceHiddenPatch

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9HonestWholeViewGames V8Smz9MeasuredRunContinuity V8Smz9MeasuredOracleHybrid
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Other Work : Type} [Fintype Other] [DecidableEq Other] [Fintype Work]

theorem sqrt_source_tape_cap : Real.sqrt ((2 ^ 512 : ℝ)⁻¹) = (2 ^ 256 : ℝ)⁻¹ := by
  have power : (2 ^ 512 : ℝ) = (2 ^ 256 : ℝ) ^ 2 := by rw [← pow_mul]
  rw [power, Real.sqrt_inv, Real.sqrt_sq (by positivity)]

/-- The complete measured interpreter, including all later honest oracle
reads and persistent fresh-input updates, cannot distinguish this one hidden
source overlay beyond the ordinary counted-query hybrid loss. A fixed prior
nonleaf override is already part of `other` and persists in both executions. -/
theorem full_source_overlay_measured_distance_le
    (randomized : Bool) (program : Program (LeafInput ⊕ Other) Work)
    (oldLeaf : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (initial : GameState (Input := LeafInput ⊕ Other) (Work := Work))
    (normalized : ‖initial‖ = 1) :
    |uniformAverage (fun hidden : LeafIndex → LeafTape =>
        V8Smz9HonestWholeViewGames.run randomized program
          (fullSourceOverlay oldLeaf other targets unopened header suffix hidden) initial) -
      V8Smz9HonestWholeViewGames.run randomized program (Sum.elim oldLeaf other) initial| ≤
      4 * (queryCount program : ℝ) / (2 ^ 256 : ℝ) := by
  let support := indexedSupport
    (Sum.elim rawInputIndex (fun _ : Other => 0))
    (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape)))
  have supportBound (input : LeafInput ⊕ Other) :
      supportCount support input ≤ (Fintype.card (LeafIndex → LeafTape) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
    (indexed_leaf_tape_support_count
      (Sum.elim rawInputIndex (fun _ : Other => 0))
      (Sum.elim leafTapeProjection (fun _ : Other => (0 : LeafTape))) input).le
  have same (hidden : LeafIndex → LeafTape) (input : LeafInput ⊕ Other)
      (outside : input ∉ support hidden) :
      Sum.elim oldLeaf other input = fullSourceOverlay oldLeaf other targets unopened header suffix hidden input := by
    cases input with
    | inl input =>
        have outsideLeaf := inl_not_indexed_support rawInputIndex leafTapeProjection
          0 (0 : LeafTape) hidden input outside
        have outsideSource := outside_of_subset _ _
          (source_patch_support_subset unopened header suffix hidden) input outsideLeaf
        simp only [fullSourceOverlay, Sum.elim_inl, sourceOverlay, if_neg outsideSource]
    | inr input => rfl
  have hybrid := measured_program_hidden_patch_bound randomized program support
    (2 ^ 512 : ℝ)⁻¹ (by positivity)
    (inv_le_one_of_one_le₀ (one_le_pow₀ (by norm_num))) supportBound (Sum.elim oldLeaf other)
    (fullSourceOverlay oldLeaf other targets unopened header suffix) same initial
  have observation := average_difference_abs_le
    (fun hidden : LeafIndex → LeafTape => V8Smz9HonestWholeViewGames.run randomized program
      (fullSourceOverlay oldLeaf other targets unopened header suffix hidden) initial)
    (fun _ : LeafIndex → LeafTape =>
      V8Smz9HonestWholeViewGames.run randomized program (Sum.elim oldLeaf other) initial)
  rw [uniform_average_const] at observation
  have result := observation.trans hybrid
  simpa only [queryLoss, normalized, one_pow, mul_one, sqrt_source_tape_cap, div_eq_mul_inv] using result

/-- A two-raw-query implementation of each counted logical read pays the
requested `8 q / 2^256`. The measured semantics and hidden-patch distance are
proved; the only compiler-side premise is the ordinary worst-case query count. -/
theorem full_source_overlay_measured_logical_budget_le
    (randomized : Bool) (program : Program (LeafInput ⊕ Other) Work)
    (oldLeaf : LeafInput → DigestRegister) (other : Other → DigestRegister)
    (targets : LeafIndex → DigestRegister) (unopened : Finset LeafIndex)
    (header : LeafIndex → LeafHeader) (suffix : LeafIndex → LeafSuffix)
    (initial : GameState (Input := LeafInput ⊕ Other) (Work := Work))
    (normalized : ‖initial‖ = 1) (budget : Nat)
    (queryBound : queryCount program ≤ 2 * budget) :
    |uniformAverage (fun hidden : LeafIndex → LeafTape =>
        V8Smz9HonestWholeViewGames.run randomized program
          (fullSourceOverlay oldLeaf other targets unopened header suffix hidden) initial) -
      V8Smz9HonestWholeViewGames.run randomized program (Sum.elim oldLeaf other) initial| ≤
      8 * (budget : ℝ) / (2 ^ 256 : ℝ) := by
  apply (full_source_overlay_measured_distance_le randomized program oldLeaf other targets unopened
    header suffix initial normalized).trans
  have castBound : (queryCount program : ℝ) ≤ 2 * (budget : ℝ) := by exact_mod_cast queryBound
  have scaled := div_le_div_of_nonneg_right
    (mul_le_mul_of_nonneg_left castBound (by norm_num : (0 : ℝ) ≤ 4))
    (by positivity : (0 : ℝ) ≤ 2 ^ 256)
  convert scaled using 1
  ring


end
end HegemonCrypto.SmallWood.V8Smz9MeasuredSourceHiddenPatch
