import SmzaRp05DecsPointProjection
import Q38Rp05CurrentCosetCertificate
import HegemonCrypto.SmallWoodV8Smz9DisjointCoset
import HegemonCrypto.SmallWoodV8Smz9HiddenPatch

/-!
# Current SMZA q38 disjoint-coset points

The old q20 descriptor has a fixed 388-point interpolation domain. Current
SMZA instead derives the descriptor from 368 LVCS columns plus 38 opened
leaves, so its complete interpolation domain has 406 points. This module
connects the current source projection to that q38 geometry; no proof bytes
or sampler behavior are changed.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentDisjointCoset

open HegemonCrypto.SmallWood.SmzaRp05DecsPointProjection
open HegemonCrypto.SmallWood
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

set_option autoImplicit false

def interpolationPointCount : Nat := 406

def indexedPoint
    (index : HegemonCrypto.SmallWood.V8Smz9HiddenPatch.LeafIndex) : Goldilocks :=
  (406 : Goldilocks) * radix2Root ^ index.val

private theorem current_root_eq_historical :
    radix2Root = HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2Root := by
  norm_num [radix2Root,
    HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2Root,
    HegemonCrypto.SmallWood.V8Smz9DisjointCoset.goldilocksTwoAdicRoot]

theorem current_candidate_406_valid : disjointCandidate 406 406 = true := by
  exact HegemonCrypto.SmallWood.Q38Rp05CurrentCosetCertificate.current_candidate_406_valid

theorem current_shift_is_406 : disjointCosetShift 406 = some (406 : Goldilocks) := by
  have first : ((List.range searchLimit).map (406 + ·)).find?
      (disjointCandidate 406) = some 406 := by
    rw [show searchLimit = 4095 + 1 from rfl,
      List.range_succ_eq_map]
    simp only [List.map_cons, Nat.add_zero,
      List.find?_cons_of_pos current_candidate_406_valid]
  simp [disjointCosetShift, first, domainSize]

theorem current_field_point_exact
    (index : HegemonCrypto.SmallWood.V8Smz9HiddenPatch.LeafIndex) :
    fieldPoint 406 index.val = some (indexedPoint index) := by
  simp [fieldPoint, indexedPoint, current_shift_is_406, domainSize, index.isLt]

theorem radix2_root_ne_zero : radix2Root ≠ 0 := by
  intro zero
  have domainNonzero : domainSize ≠ 0 := by norm_num [domainSize]
  have rootPower : radix2Root ^ domainSize = 0 := by
    simp [zero, domainNonzero]
  have rootOrder : radix2Root ^ domainSize = 1 := by
    change
      HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2Root ^
        HegemonCrypto.SmallWood.V8Smz9DisjointCoset.domainSize = 1
    exact HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2_root_pow_domain
  rw [rootOrder] at rootPower
  norm_num at rootPower

theorem current_point_injective :
    Function.Injective
      (fun index : HegemonCrypto.SmallWood.V8Smz9HiddenPatch.LeafIndex => indexedPoint index) := by
  intro left right same
  have shiftNe : (406 : Goldilocks) ≠ 0 := by decide
  have powersSame : radix2Root ^ left.val = radix2Root ^ right.val :=
    mul_left_cancel₀ shiftNe (by simpa [indexedPoint] using same)
  have finiteOrder : IsOfFinOrder radix2Root :=
    isOfFinOrder_iff_pow_eq_one.mpr
      ⟨domainSize, by simp [domainSize], by
        simpa [current_root_eq_historical, domainSize,
          HegemonCrypto.SmallWood.V8Smz9DisjointCoset.domainSize] using
          HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2_root_pow_domain⟩
  have equalRemainders :=
    (finiteOrder.pow_inj_mod (n := left.val) (m := right.val)).mp powersSame
  have rootOrder : orderOf radix2Root = domainSize := by
    simpa [current_root_eq_historical, domainSize,
      HegemonCrypto.SmallWood.V8Smz9DisjointCoset.domainSize] using
      HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2_root_order
  rw [rootOrder] at equalRemainders
  have leftReduced : left.val % domainSize = left.val := Nat.mod_eq_of_lt left.isLt
  have rightReduced : right.val % domainSize = right.val := Nat.mod_eq_of_lt right.isLt
  rw [leftReduced, rightReduced] at equalRemainders
  exact Fin.ext equalRemainders

theorem current_domain_point_avoids_node
    (index : HegemonCrypto.SmallWood.V8Smz9HiddenPatch.LeafIndex)
    (node : Fin 406) : indexedPoint index ≠ (node.val : Goldilocks) := by
  intro equal
  have shiftNe : (406 : Goldilocks) ≠ 0 := by decide
  have nodeCondition :
      node.val = 0 ∨
        ((node.val : Goldilocks) * (406 : Goldilocks)⁻¹) ^ domainSize ≠ 1 := by
    have candidate := current_candidate_406_valid
    simp only [disjointCandidate, Bool.and_eq_true] at candidate
    have allNodes :
        (List.range 406).all (fun point => decide
          (point = 0 ∨
            ((point : Goldilocks) * (406 : Goldilocks)⁻¹) ^ domainSize ≠ 1)) = true :=
      by simpa using candidate.2
    have member : node.val ∈ List.range 406 := List.mem_range.mpr node.isLt
    exact of_decide_eq_true ((List.all_eq_true.mp allNodes) node.val member)
  rcases nodeCondition with nodeZero | disjoint
  · have pointNeZero : indexedPoint index ≠ 0 := by
      rw [indexedPoint]
      exact mul_ne_zero shiftNe (pow_ne_zero _ radix2_root_ne_zero)
    apply pointNeZero
    rw [equal, nodeZero]
    simp
  · apply disjoint
    have ratio :
        (node.val : Goldilocks) * (406 : Goldilocks)⁻¹ = radix2Root ^ index.val := by
      calc
        (node.val : Goldilocks) * (406 : Goldilocks)⁻¹ =
            indexedPoint index * (406 : Goldilocks)⁻¹ :=
          congrArg (fun value : Goldilocks => value * (406 : Goldilocks)⁻¹) equal.symm
        _ = (406 : Goldilocks) * radix2Root ^ index.val * (406 : Goldilocks)⁻¹ := by
          rw [indexedPoint]
        _ = radix2Root ^ index.val := by
          calc
            (406 : Goldilocks) * radix2Root ^ index.val * (406 : Goldilocks)⁻¹ =
                ((406 : Goldilocks) * (406 : Goldilocks)⁻¹) * radix2Root ^ index.val := by
                  ac_rfl
            _ = radix2Root ^ index.val := by
              rw [mul_inv_cancel₀ shiftNe, one_mul]
    have rootPower : (radix2Root ^ index.val) ^ domainSize = 1 := by
      calc
        (radix2Root ^ index.val) ^ domainSize =
            radix2Root ^ (index.val * domainSize) := by rw [pow_mul]
        _ = radix2Root ^ (domainSize * index.val) := by rw [Nat.mul_comm]
        _ = (radix2Root ^ domainSize) ^ index.val := by rw [pow_mul]
        _ = 1 := by
          change
            (HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2Root ^
              HegemonCrypto.SmallWood.V8Smz9DisjointCoset.domainSize) ^ index.val = 1
          rw [HegemonCrypto.SmallWood.V8Smz9DisjointCoset.radix2_root_pow_domain, one_pow]
    rw [ratio]
    exact rootPower

end HegemonCrypto.SmallWood.Q38Rp05CurrentDisjointCoset
