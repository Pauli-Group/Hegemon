import HegemonCrypto.Goldilocks
import Mathlib.GroupTheory.OrderOfElement

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

/-!
# Exact SMZ9 disjoint-coset evaluation domain

This module gives a field-level certificate for the constants corresponding to
`SmallwoodDisjointCosetDescriptorV1::derive(2^23, 388)`.  It proves that the first candidate,
shift 388, is already disjoint.  Connecting the Rust search/control flow and byte-level field
operations to these Lean definitions remains a separate executable-refinement theorem.
-/

namespace HegemonCrypto.SmallWood.V8Smz9DisjointCoset

open HegemonCrypto.SmallWood

def domainSize : Nat := 2 ^ 23
def interpolationPointCount : Nat := 388

/-- The same Goldilocks two-adic root used by the Rust evaluator. -/
def goldilocksTwoAdicRoot : Goldilocks :=
  (0x185629dcda58878c : Nat)

/-- The subgroup generator specified by the exact `2^23` descriptor. -/
def radix2Root : Goldilocks :=
  goldilocksTwoAdicRoot ^ (2 ^ 9)

/-- The first candidate specified by the source search contract. -/
def cosetShift : Goldilocks :=
  (interpolationPointCount : Nat)

theorem exact_domain_descriptor :
    domainSize = 8388608 ∧ interpolationPointCount = 388 ∧
      cosetShift = (388 : Goldilocks) := by
  decide

theorem radix2_root_pow_domain :
    radix2Root ^ domainSize = 1 := by
  change
    ((1753635133440165772 : ZMod 18446744069414584321) ^ (2 ^ 9)) ^
        (2 ^ 23) = 1
  calc
    _ =
        (1753635133440165772 : ZMod 18446744069414584321) ^
          ((2 ^ 9) * (2 ^ 23)) :=
      (pow_mul (1753635133440165772 : ZMod 18446744069414584321)
        (2 ^ 9) (2 ^ 23)).symm
    _ = 1 := by
      reduce_mod_char

theorem radix2_root_pow_half_ne_one :
    radix2Root ^ (2 ^ 22) ≠ 1 := by
  change
    ((1753635133440165772 : ZMod 18446744069414584321) ^ (2 ^ 9)) ^
        (2 ^ 22) ≠ 1
  intro equality
  have combined :
      (1753635133440165772 : ZMod 18446744069414584321) ^
          ((2 ^ 9) * (2 ^ 22)) = 1 := by
    calc
      _ =
          ((1753635133440165772 : ZMod 18446744069414584321) ^ (2 ^ 9)) ^
            (2 ^ 22) :=
        pow_mul (1753635133440165772 : ZMod 18446744069414584321)
          (2 ^ 9) (2 ^ 22)
      _ = 1 := equality
  reduce_mod_char at combined
  have representativeEquality := congrArg ZMod.val combined
  change 18446744069414584320 = 1 at representativeEquality
  omega

theorem radix2_root_order :
    orderOf radix2Root = domainSize := by
  simpa [domainSize] using
    (orderOf_eq_prime_pow
      (p := 2)
      (n := 22)
      (x := radix2Root)
      radix2_root_pow_half_ne_one
      radix2_root_pow_domain)

/-- Point formula corresponding to `SmallwoodDisjointCosetDescriptorV1::point_for_leaf_index`. -/
def evaluationPoint (index : Fin domainSize) : Goldilocks :=
  cosetShift * radix2Root ^ index.val

theorem coset_shift_ne_zero : cosetShift ≠ 0 := by
  decide

theorem evaluation_point_injective :
    Function.Injective evaluationPoint := by
  intro left right equalPoints
  have equalPowers :
      radix2Root ^ left.val = radix2Root ^ right.val := by
    exact mul_left_cancel₀ coset_shift_ne_zero equalPoints
  have finiteOrder : IsOfFinOrder radix2Root :=
    isOfFinOrder_iff_pow_eq_one.mpr
      ⟨domainSize, by simp [domainSize], radix2_root_pow_domain⟩
  have equalRemainders :=
    (finiteOrder.pow_inj_mod (n := left.val) (m := right.val)).mp equalPowers
  rw [radix2_root_order] at equalRemainders
  have leftReduced : left.val % domainSize = left.val :=
    Nat.mod_eq_of_lt left.isLt
  have rightReduced : right.val % domainSize = right.val :=
    Nat.mod_eq_of_lt right.isLt
  rw [leftReduced, rightReduced] at equalRemainders
  exact Fin.ext equalRemainders

theorem evaluation_point_pow_domain (index : Fin domainSize) :
    evaluationPoint index ^ domainSize = cosetShift ^ domainSize := by
  have rootPower :
      (radix2Root ^ index.val) ^ domainSize = 1 := by
    calc
      _ = radix2Root ^ (index.val * domainSize) :=
        (pow_mul radix2Root index.val domainSize).symm
      _ = radix2Root ^ (domainSize * index.val) := by
        rw [Nat.mul_comm index.val domainSize]
      _ = (radix2Root ^ domainSize) ^ index.val :=
        pow_mul radix2Root domainSize index.val
      _ = 1 := by rw [radix2_root_pow_domain, one_pow]
  rw [evaluationPoint, mul_pow, rootPower, mul_one]

/-- Executable certificate for all 388 source interpolation coordinates. -/
private theorem all_interpolation_point_powers_ne_coset_power :
    ∀ point : Fin interpolationPointCount,
      (point.val : Goldilocks) ^ domainSize ≠ cosetShift ^ domainSize := by
  have concrete : ∀ point : Fin 388,
      (point.val : ZMod 18446744069414584321) ^ (2 ^ 23) ≠
        ((388 : Nat) : ZMod 18446744069414584321) ^ (2 ^ 23) := by
    intro point
    fin_cases point <;> reduce_mod_char <;> decide
  intro point
  change
    (point.val : ZMod 18446744069414584321) ^ (2 ^ 23) ≠
      ((388 : Nat) : ZMod 18446744069414584321) ^ (2 ^ 23)
  exact concrete point

theorem interpolation_point_power_ne_coset_power
    (point : Fin interpolationPointCount) :
    (point.val : Goldilocks) ^ domainSize ≠ cosetShift ^ domainSize :=
  all_interpolation_point_powers_ne_coset_power point

/-- Shift 388 passes the complete field-level disjointness condition. -/
theorem disjoint_from_interpolation_domain
    (index : Fin domainSize)
    (point : Fin interpolationPointCount) :
    evaluationPoint index ≠ (point.val : Goldilocks) := by
  intro equalPoint
  have powered := congrArg (fun value : Goldilocks => value ^ domainSize) equalPoint
  rw [evaluation_point_pow_domain] at powered
  exact interpolation_point_power_ne_coset_power point powered.symm

/-- The first specified candidate is field-valid; Rust control-flow refinement is separate. -/
theorem first_candidate_is_field_valid :
    cosetShift = (388 : Goldilocks) ∧
      (∀ index : Fin domainSize, ∀ point : Fin interpolationPointCount,
        evaluationPoint index ≠ (point.val : Goldilocks)) := by
  refine ⟨by rfl, ?_⟩
  exact fun index point => disjoint_from_interpolation_domain index point

end HegemonCrypto.SmallWood.V8Smz9DisjointCoset
