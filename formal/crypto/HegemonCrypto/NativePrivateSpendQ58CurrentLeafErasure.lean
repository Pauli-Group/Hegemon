import HegemonCrypto.NativePrivateSpendQ58CurrentInitializedPublic
import HegemonCrypto.SmallWoodV8Smz9MeasuredSourceHiddenPatch

/-! Instantiate the retained PR205 measured hidden-patch theorem on CURRENT
2054-byte source leaves and their806-byte tape offset. Every complete public
continuation, including aborts, keeps its original gates/instruments and raw
table. This is the concrete erasure primitive, not a supplied equality between
the entire native request and the public request constructor. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLeafErasure
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9MeasuredRunContinuity V8Smz9MeasuredOracleHybrid
open NativePrivateSpendQ58CurrentLeafInput
open NativePrivateSpendQ58CurrentCosetSelector
open scoped Classical ENNReal
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def currentSourcePatch
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Index → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (unopened : Finset Index) (hidden : Index → LeafTape) : Finset CurrentLeafInput :=
  unopened.image fun index => NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput
    statement salt (payload index) index (hidden index)

def currentSourceOverlay {bound : Nat} (old : CurrentFullRawInput bound → DigestRegister)
    (labels : Index → DigestRegister)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Index → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (unopened : Finset Index) (hidden : Index → LeafTape) :
    CurrentFullRawInput bound → DigestRegister
  | .inl input =>
      if input ∈ currentSourcePatch statement salt payload unopened hidden then
        labels (indexProjection input) else old (.inl input)
  | .inr input => old (.inr input)

theorem current_patch_subset
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Index → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (unopened : Finset Index) (hidden : Index → LeafTape) :
    currentSourcePatch statement salt payload unopened hidden ⊆
      indexedSupport indexProjection tapeProjection hidden := by
  intro input member
  obtain ⟨index, _member, rfl⟩ := Finset.mem_image.mp member
  simp only [indexedSupport, Finset.mem_filter, Finset.mem_univ, true_and]
  rw [NativePrivateSpendQ58CurrentLeafInput.source_leaf_index,
    NativePrivateSpendQ58CurrentLeafInput.source_leaf_tape]

theorem current_nonleaf_overlay {bound : Nat}
    (old : CurrentFullRawInput bound → DigestRegister) (labels : Index → DigestRegister)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Index → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (unopened : Finset Index) (hidden : Index → LeafTape) (input : CurrentOtherRawInput bound) :
    currentSourceOverlay old labels statement salt payload unopened hidden (.inr input) = old (.inr input) := rfl

/-- Same measured hidden-patch loss as PR205, now on the collision-exact
current byte carrier. No current target-rank or whole-view equality is assumed.
The state must be independent of the hidden UNOPENED tapes; exposed tapes may
already be fixed in the public prefix, ordinary oracle and continuation. -/
theorem current_unopened_erasure_bound {bound : Nat} {Work : Type} [Fintype Work]
    (randomized : Bool)
    (program : V8Smz9HonestWholeViewGames.Program (CurrentFullRawInput bound) Work)
    (old : CurrentFullRawInput bound → DigestRegister) (labels : Index → DigestRegister)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Index → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (unopened : Finset Index)
    (initial : V8Smz9HonestWholeViewGames.GameState (Input := CurrentFullRawInput bound) (Work := Work))
    (normalized : ‖initial‖ = 1) :
    |uniformAverage (fun hidden : Index → LeafTape =>
        V8Smz9HonestWholeViewGames.run randomized program
          (currentSourceOverlay old labels statement salt payload unopened hidden) initial) -
      V8Smz9HonestWholeViewGames.run randomized program old initial| ≤
      4 * (V8Smz9HonestWholeViewGames.queryCount program : ℝ) / (2 ^ 256 : ℝ) := by
  let support := indexedSupport
    (Sum.elim indexProjection (fun _ : CurrentOtherRawInput bound => (0 : Index)))
    (Sum.elim tapeProjection (fun _ : CurrentOtherRawInput bound => (0 : LeafTape)))
  have supportBound (input : CurrentFullRawInput bound) :
      supportCount support input ≤ (Fintype.card (Index → LeafTape) : ℝ) * (2 ^ 512 : ℝ)⁻¹ :=
    (indexed_leaf_tape_support_count
      (Sum.elim indexProjection (fun _ : CurrentOtherRawInput bound => (0 : Index)))
      (Sum.elim tapeProjection (fun _ : CurrentOtherRawInput bound => (0 : LeafTape))) input).le
  have same (hidden : Index → LeafTape) (input : CurrentFullRawInput bound)
      (outside : input ∉ support hidden) :
      old input = currentSourceOverlay old labels statement salt payload unopened hidden input := by
    cases input with
    | inl input =>
        have outsideLeaf := inl_not_indexed_support indexProjection tapeProjection
          (0 : Index) (0 : LeafTape) hidden input outside
        have outsideSource := outside_of_subset _ _
          (current_patch_subset statement salt payload unopened hidden) input outsideLeaf
        simp only [currentSourceOverlay, if_neg outsideSource]
    | inr input => rfl
  have hybrid := measured_program_hidden_patch_bound randomized program support
    (2 ^ 512 : ℝ)⁻¹ (by positivity)
    (inv_le_one_of_one_le₀ (one_le_pow₀ (by norm_num))) supportBound old
    (currentSourceOverlay old labels statement salt payload unopened) same initial
  have observation := average_difference_abs_le
    (fun hidden : Index → LeafTape => V8Smz9HonestWholeViewGames.run randomized program
      (currentSourceOverlay old labels statement salt payload unopened hidden) initial)
    (fun _ : Index → LeafTape => V8Smz9HonestWholeViewGames.run randomized program old initial)
  rw [uniform_average_const] at observation
  have result := observation.trans hybrid
  simpa only [queryLoss, normalized, one_pow, mul_one,
    V8Smz9MeasuredSourceHiddenPatch.sqrt_source_tape_cap, div_eq_mul_inv] using result

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentLeafErasure
