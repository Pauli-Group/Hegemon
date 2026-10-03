import HegemonCrypto.SmallWoodV8Smz9DisjointCoset
import SmzaRp05DecsPointProjection
import Q38Rp05CurrentDisjointCoset

/-!
# Current RP05 406-point disjoint coset

The source derives its shift from `368 + 38 = 406`, not the historical
`368 + 20 = 388`. Preserve the historical theorem and define the current map
separately. The finite certificate below checks every current interpolation
coordinate; the root/order facts are reused unchanged. The search theorem
also connects the current map to the literal source-shaped fieldPoint.

At leaf zero, the historical map equals388 and therefore lies IN the current
interpolation set. The two maps must not be identified in a soundness join.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406

set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 1000000

def domainSize : Nat := 2 ^ 23
def interpolationPointCount : Nat := 406
def cosetShift : Goldilocks := 406
abbrev radix2Root := V8Smz9DisjointCoset.radix2Root

def evaluationPoint (index : Fin domainSize) : Goldilocks :=
  cosetShift * radix2Root ^ index.val

theorem coset_shift_ne_zero : cosetShift ≠ 0 := by decide

theorem evaluation_point_injective : Function.Injective evaluationPoint := by
  intro left right equal
  have powers : radix2Root ^ left.val = radix2Root ^ right.val :=
    mul_left_cancel₀ coset_shift_ne_zero equal
  apply V8Smz9DisjointCoset.evaluation_point_injective
  change V8Smz9DisjointCoset.cosetShift * radix2Root ^ left.val =
    V8Smz9DisjointCoset.cosetShift * radix2Root ^ right.val
  rw [powers]

theorem evaluation_point_pow_domain (index : Fin domainSize) :
    evaluationPoint index ^ domainSize = cosetShift ^ domainSize := by
  have rootPower : (radix2Root ^ index.val) ^ domainSize = 1 := by
    calc
      _ = radix2Root ^ (index.val * domainSize) :=
        (pow_mul radix2Root index.val domainSize).symm
      _ = radix2Root ^ (domainSize * index.val) := by
        rw [Nat.mul_comm index.val domainSize]
      _ = (radix2Root ^ domainSize) ^ index.val :=
        pow_mul radix2Root domainSize index.val
      _ = 1 := by
        change
          (V8Smz9DisjointCoset.radix2Root ^
            V8Smz9DisjointCoset.domainSize) ^ index.val = 1
        rw [V8Smz9DisjointCoset.radix2_root_pow_domain, one_pow]
  rw [evaluationPoint, mul_pow, rootPower, mul_one]

/-- Rebind the separately certified current-profile coset to this extraction API. -/
theorem disjoint_from_interpolation_domain (index : Fin domainSize)
    (point : Fin interpolationPointCount) :
    evaluationPoint index ≠ (point.val : Goldilocks) := by
  let leaf : HegemonCrypto.SmallWood.V8Smz9HiddenPatch.LeafIndex :=
    ⟨index.val, index.isLt⟩
  change Q38Rp05CurrentDisjointCoset.indexedPoint leaf ≠ (point.val : Goldilocks)
  exact Q38Rp05CurrentDisjointCoset.current_domain_point_avoids_node leaf point

theorem source_candidate_is_disjoint :
    SmzaRp05DecsPointProjection.disjointCandidate 406 406 = true := by
  exact Q38Rp05CurrentDisjointCoset.current_candidate_406_valid

theorem source_search_returns_406 :
    SmzaRp05DecsPointProjection.disjointCosetShift 406 = some cosetShift := by
  have first : ((List.range SmzaRp05DecsPointProjection.searchLimit).map (406 + ·)).find?
      (SmzaRp05DecsPointProjection.disjointCandidate 406) = some 406 := by
    rw [show SmzaRp05DecsPointProjection.searchLimit = 4095 + 1 from rfl,
      List.range_succ_eq_map]
    simp only [List.map_cons, Nat.add_zero,
      List.find?_cons_of_pos source_candidate_is_disjoint]
  simp [SmzaRp05DecsPointProjection.disjointCosetShift, first,
    SmzaRp05DecsPointProjection.domainSize, cosetShift]

theorem source_field_point_is_current (index : Fin domainSize) :
    SmzaRp05DecsPointProjection.fieldPoint 406 index.val = some (evaluationPoint index) := by
  have bound : ¬ index.val ≥ SmzaRp05DecsPointProjection.domainSize := Nat.not_le.mpr index.isLt
  simp only [SmzaRp05DecsPointProjection.fieldPoint, if_neg bound,
    source_search_returns_406]
  rfl

/-- Concrete legacy counterexample: x=388 is now an interpolation point. -/
theorem historical_leaf_zero_hits_current_interpolation :
    V8Smz9DisjointCoset.evaluationPoint ⟨0, by decide⟩ =
      ((⟨388, by decide⟩ : Fin interpolationPointCount).val : Goldilocks) := by
  simp [V8Smz9DisjointCoset.evaluationPoint, V8Smz9DisjointCoset.cosetShift,
    V8Smz9DisjointCoset.interpolationPointCount]

theorem current_leaf_zero_differs_from_historical :
    evaluationPoint ⟨0, by decide⟩ ≠
      V8Smz9DisjointCoset.evaluationPoint ⟨0, by decide⟩ := by
  simp only [evaluationPoint, V8Smz9DisjointCoset.evaluationPoint, pow_zero, mul_one,
    cosetShift, V8Smz9DisjointCoset.cosetShift, V8Smz9DisjointCoset.interpolationPointCount]
  decide

end HegemonCrypto.SmallWood.SmzaRp05CurrentCoset406
