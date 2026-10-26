import SmzaRp05DecsPointProjection
import HegemonCrypto.SmallWoodV8Smz9DisjointCoset

/-! One actual successful current lookup supplies the source-selected shift.
The proof uses its checked natural nonzero/canonical predicate and the common
root-order law. It does not evaluate the search or identify a fixed shift.
SOURCE PROPOSAL ONLY: kernel pending; no accepted-wire or mass claim. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPointGeometry

namespace DP
export SmzaRp05DecsPointProjection
  (domainSize searchLimit radix2Root disjointCandidate disjointCosetShift fieldPoint)
end DP

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

def currentPoint (position : Fin 8388608) : Goldilocks :=
  (DP.fieldPoint 13173 position.val).getD 0

/-- A selected source shift is nonzero in the field, not merely as a Nat. -/
theorem selected_shift_nonzero (shift : Goldilocks)
    (selected : DP.disjointCosetShift 13173 = some shift) : shift ≠ 0 := by
  have allowed : ¬ (13173 = 0 ∨ 13173 > DP.domainSize) := by decide
  have selectionFormula : DP.disjointCosetShift 13173 =
      (((List.range DP.searchLimit).map (13173 + ·)).find?
        (DP.disjointCandidate 13173)).bind
          (fun candidate => some (candidate : Goldilocks)) := by
    unfold DP.disjointCosetShift
    rw [if_neg allowed]
    rfl
  rw [selectionFormula] at selected
  generalize found : ((List.range DP.searchLimit).map (13173 + ·)).find?
      (DP.disjointCandidate 13173) = foundCandidate at selected
  cases foundCandidate with
  | none =>
      change (none : Option Goldilocks) = some shift at selected
      cases selected
  | some candidate =>
      change (some (candidate : Goldilocks) : Option Goldilocks) = some shift at selected
      have castEq : (candidate : Goldilocks) = shift := Option.some.inj selected
      have checked : DP.disjointCandidate 13173 candidate = true := List.find?_some found
      change ((decide (candidate ≠ 0) &&
        decide (candidate < SmzaRp05ExecutableChallengeStage.modulus)) &&
        (List.range 13173).all (fun point => decide (point = 0 ∨
          (((point : Goldilocks) * (candidate : Goldilocks)⁻¹) ^ DP.domainSize ≠ 1)))) =
            true at checked
      have prefixChecked := (Bool.and_eq_true_iff.mp checked).1
      have firstChecks := Bool.and_eq_true_iff.mp prefixChecked
      have nonzero : candidate ≠ 0 := of_decide_eq_true firstChecks.1
      have canonical : candidate < SmzaRp05ExecutableChallengeStage.modulus :=
        of_decide_eq_true firstChecks.2
      have representative : (candidate : Goldilocks).val = candidate :=
        ZMod.val_natCast_of_lt canonical
      rw [← castEq]
      intro zero
      apply nonzero
      calc
        candidate = (candidate : Goldilocks).val := representative.symm
        _ = (0 : Goldilocks).val := congrArg (fun value : Goldilocks => value.val) zero
        _ = 0 := rfl

private theorem bind_some_has_input (source : Option Goldilocks)
    (f : Goldilocks → Goldilocks) (point : Goldilocks)
    (success : source.bind (fun shift => some (f shift)) = some point) :
    ∃ shift : Goldilocks, source = some shift := by
  cases source with
  | none => cases success
  | some shift => exact ⟨shift, rfl⟩

/-- The successful point lookup yields the shift; it is never supplied. -/
theorem successful_point_has_selected_shift (sample : Fin 8388608) (point : Goldilocks)
    (success : DP.fieldPoint 13173 sample.val = some point) :
    ∃ shift : Goldilocks, DP.disjointCosetShift 13173 = some shift ∧ shift ≠ 0 := by
  have within : sample.val < DP.domainSize := sample.isLt
  unfold DP.fieldPoint at success
  rw [if_neg (not_le.mpr within)] at success
  change (DP.disjointCosetShift 13173).bind
    (fun shift => some (shift * DP.radix2Root ^ sample.val)) = some point at success
  obtain ⟨shift, selected⟩ := bind_some_has_input
    (DP.disjointCosetShift 13173) (fun shift => shift * DP.radix2Root ^ sample.val)
    point success
  exact ⟨shift, selected, selected_shift_nonzero shift selected⟩

theorem current_point_injective_from_one_success
    (sample : Fin 8388608) (point : Goldilocks)
    (success : DP.fieldPoint 13173 sample.val = some point) :
    Function.Injective currentPoint := by
  obtain ⟨shift, selected, nonzero⟩ := successful_point_has_selected_shift sample point success
  have formula : ∀ position : Fin 8388608,
      currentPoint position = shift * DP.radix2Root ^ position.val := by
    intro position
    have within : position.val < DP.domainSize := position.isLt
    have sourcePoint : DP.fieldPoint 13173 position.val =
        some (shift * DP.radix2Root ^ position.val) := by
      unfold DP.fieldPoint
      rw [if_neg (not_le.mpr within)]
      change (DP.disjointCosetShift 13173).bind
        (fun chosen => some (chosen * DP.radix2Root ^ position.val)) =
          some (shift * DP.radix2Root ^ position.val)
      rw [selected]
      rfl
    change (DP.fieldPoint 13173 position.val).getD 0 =
      shift * DP.radix2Root ^ position.val
    rw [sourcePoint]
    rfl
  have rootPower : DP.radix2Root ^ DP.domainSize = 1 :=
    V8Smz9DisjointCoset.radix2_root_pow_domain
  have rootOrder : orderOf DP.radix2Root = DP.domainSize :=
    V8Smz9DisjointCoset.radix2_root_order
  have finiteOrder : IsOfFinOrder DP.radix2Root :=
    isOfFinOrder_iff_pow_eq_one.mpr
      ⟨DP.domainSize, by simp [DP.domainSize], rootPower⟩
  intro left right equal
  rw [formula left, formula right] at equal
  have equalPowers : DP.radix2Root ^ left.val = DP.radix2Root ^ right.val :=
    mul_left_cancel₀ nonzero equal
  have equalRemainders :=
    (finiteOrder.pow_inj_mod (n := left.val) (m := right.val)).mp equalPowers
  rw [rootOrder, Nat.mod_eq_of_lt (show left.val < DP.domainSize from left.isLt),
    Nat.mod_eq_of_lt (show right.val < DP.domainSize from right.isLt)] at equalRemainders
  exact Fin.ext equalRemainders

/-- The exact requested getter, including its failure default, is injective
once one ordinary source lookup succeeds. -/
theorem field_point_getter_injective_from_one_success
    (sample : Fin 8388608) (point : Goldilocks)
    (success : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point) :
    Function.Injective (fun position : Fin 8388608 =>
      (SmzaRp05DecsPointProjection.fieldPoint 13173 position.val).getD 0) :=
  current_point_injective_from_one_success sample point success

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPointGeometry
