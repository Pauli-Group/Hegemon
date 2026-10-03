import HegemonCrypto.SmallWoodV8Smz9SemanticAssetMembership

/-!
Universal four-slot interpolation algebra for the HGV8RP03 balance proof.
Repeated padding slots contribute factors one and have weight zero. These
theorems use native field inversion and make no source-evaluation assumption.
The exact source DAG and its natural-number inverse bridge are separate work.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation

open scoped BigOperators

set_option maxHeartbeats 0

noncomputable section

variable {F : Type*} [Field F] [DecidableEq F]

def interpolationFactor (padding x candidate : F) : F :=
  if candidate = padding then 1 else x - candidate

def interpolationNumerator (assets : Nat → F) (padding : F)
    (slot : Fin 4) (x : F) : F :=
  ∏ other ∈ (Finset.univ : Finset (Fin 4)).erase slot,
    interpolationFactor padding x (assets other.val)

def interpolationWeight (assets : Nat → F) (padding : F)
    (slot : Fin 4) (x : F) : F :=
  if assets slot.val = padding then 0
  else interpolationNumerator assets padding slot x *
    (interpolationNumerator assets padding slot (assets slot.val))⁻¹

def NonpaddingDistinct (assets : Nat → F) (padding : F) : Prop :=
  ∀ left right : Fin 4, left ≠ right →
    assets left.val ≠ padding → assets right.val ≠ padding →
    assets left.val ≠ assets right.val

theorem interpolation_denominator_ne_zero
    (assets : Nat → F) (padding : F) (slot : Fin 4)
    (distinct : NonpaddingDistinct assets padding)
    (nonpadding : assets slot.val ≠ padding) :
    interpolationNumerator assets padding slot (assets slot.val) ≠ 0 := by
  apply Finset.prod_ne_zero_iff.mpr
  intro other member
  have different : slot ≠ other := (Finset.mem_erase.mp member).1.symm
  by_cases otherPadding : assets other.val = padding
  · simp [interpolationFactor, otherPadding]
  · simpa only [interpolationFactor, if_neg otherPadding, sub_ne_zero] using
      distinct slot other different nonpadding otherPadding

theorem interpolation_numerator_zero_at_other
    (assets : Nat → F) (padding : F) (slot chosen : Fin 4)
    (different : chosen ≠ slot) (nonpadding : assets chosen.val ≠ padding) :
    interpolationNumerator assets padding slot (assets chosen.val) = 0 := by
  apply Finset.prod_eq_zero (Finset.mem_erase.mpr ⟨different, Finset.mem_univ chosen⟩)
  simp [interpolationFactor, nonpadding]

/-- At any admitted nonpadding asset, the field weight is its exact indicator. -/
theorem interpolationWeight_eq_indicator
    (assets : Nat → F) (padding : F) (slot : Fin 4) (x : F)
    (distinct : NonpaddingDistinct assets padding)
    (member : ∃ chosen : Fin 4, assets chosen.val ≠ padding ∧ x = assets chosen.val) :
    interpolationWeight assets padding slot x =
      if x = assets slot.val then 1 else 0 := by
  obtain ⟨chosen, chosenReal, matched⟩ := member
  by_cases slotPadding : assets slot.val = padding
  · have different : x ≠ assets slot.val := by
      intro equal
      exact chosenReal (matched.symm.trans (equal.trans slotPadding))
    simp only [interpolationWeight, if_pos slotPadding, if_neg different]
  · by_cases equal : x = assets slot.val
    · have denominator := interpolation_denominator_ne_zero assets padding slot distinct slotPadding
      simp [interpolationWeight, slotPadding, equal, denominator]
    · have different : chosen ≠ slot := by
        intro same
        exact equal (by simpa only [same] using matched)
      have zero := interpolation_numerator_zero_at_other assets padding slot chosen
        different chosenReal
      rw [interpolationWeight, if_neg slotPadding, if_neg equal, matched, zero, zero_mul]

theorem interpolationWeight_eq_one_iff
    (assets : Nat → F) (padding : F) (slot : Fin 4) (x : F)
    (distinct : NonpaddingDistinct assets padding)
    (member : ∃ chosen : Fin 4, assets chosen.val ≠ padding ∧ x = assets chosen.val) :
    interpolationWeight assets padding slot x = 1 ↔ x = assets slot.val := by
  rw [interpolationWeight_eq_indicator assets padding slot x distinct member]
  by_cases equal : x = assets slot.val <;> simp [equal]

theorem interpolationWeight_eq_zero_iff
    (assets : Nat → F) (padding : F) (slot : Fin 4) (x : F)
    (distinct : NonpaddingDistinct assets padding)
    (member : ∃ chosen : Fin 4, assets chosen.val ≠ padding ∧ x = assets chosen.val) :
    interpolationWeight assets padding slot x = 0 ↔ x ≠ assets slot.val := by
  rw [interpolationWeight_eq_indicator assets padding slot x distinct member]
  by_cases equal : x = assets slot.val <;> simp [equal]

/-- Ordered three-factor form matching the source's omitted-slot products. -/
def interpolationThreeFactors (assets : Nat → F) (padding : F)
    (slot : Fin 4) (x : F) : F :=
  let factor := fun index => interpolationFactor padding x (assets index)
  match slot.val with
  | 0 => (factor 1 * factor 2) * factor 3
  | 1 => (factor 0 * factor 2) * factor 3
  | 2 => (factor 0 * factor 1) * factor 3
  | _ => (factor 0 * factor 1) * factor 2

theorem interpolationNumerator_eq_three_factors
    (assets : Nat → F) (padding : F) (slot : Fin 4) (x : F) :
    interpolationNumerator assets padding slot x =
      interpolationThreeFactors assets padding slot x := by
  have finite : slot = 0 ∨ slot = 1 ∨ slot = 2 ∨ slot = 3 := by
    have bound := slot.isLt
    omega
  have erased : ∀ selected : Fin 4, (Finset.univ : Finset (Fin 4)).erase selected =
      match selected.val with
      | 0 => {1, 2, 3}
      | 1 => {0, 2, 3}
      | 2 => {0, 1, 3}
      | _ => {0, 1, 2} := by decide
  rw [interpolationNumerator, erased slot]
  rcases finite with rfl | rfl | rfl | rfl <;>
    simp [interpolationThreeFactors, mul_assoc]

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange (canonical_nat_cast_injective)

/-- Public canonical ordering provides the field distinctness used above. -/
theorem canonical_balance_assets_nonpadding_distinct
    (assets : List Nat) (canonical : CanonicalBalanceAssets assets) :
    NonpaddingDistinct (fun index => (wordAt assets index : Goldilocks))
      (balancePaddingAssetId : Goldilocks) := by
  intro left right different leftReal rightReal equal
  have leftBound : wordAt assets left.val < fieldModulus :=
    canonical.2.2.1 left.val left.isLt
  have rightBound : wordAt assets right.val < fieldModulus :=
    canonical.2.2.1 right.val right.isLt
  have leftRealNat : wordAt assets left.val ≠ balancePaddingAssetId := by
    intro same
    exact leftReal (by simp only [same])
  have rightRealNat : wordAt assets right.val ≠ balancePaddingAssetId := by
    intro same
    exact rightReal (by simp only [same])
  have equalNat := canonical_nat_cast_injective leftBound rightBound equal
  have indexDifferent : left.val ≠ right.val := by
    intro same
    exact different (Fin.ext same)
  rcases lt_or_gt_of_ne indexDifferent with ordered | ordered
  · have strict := canonical.2.2.2.1 left.val right.val ordered right.isLt
      leftRealNat rightRealNat
    omega
  · have strict := canonical.2.2.2.1 right.val left.val ordered left.isLt
      rightRealNat leftRealNat
    omega

end

end HegemonCrypto.SmallWood.V8Smz9SemanticInterpolation
