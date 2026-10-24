import HegemonCrypto.SmallWoodV8Smz9DisjointCoset
import HegemonCrypto.NativeLaunchRelationModelResponse
import Mathlib.Data.List.Chain
import Mathlib.Data.List.OfFn

/-! Guard-derived geometry for ANY accepted canonical nonzero shift. Only the
cached exact radix2Root/order certificate is reused, never the old388shift or
its interpolation certificate. Adjacent comparisons model windows(2), not an
all-pairs injectivity guard. Search selection, actual accepted-wire refinement,
Rust arithmetic, causal chronology, QROM and launch qualification remain open. -/
set_option autoImplicit false
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchGuardedPointGeometry
open SmallWood SmallWood.V8Smz9DisjointCoset
open SmallWood.NativeLaunchRelationModelResponse
abbrev Position := Fin domainSize
def modulus : Nat := 18446744069414584321

def shiftGuard (shift : Nat) : Bool := decide (shift ≠ 0 ∧ shift < modulus)

/-- Loop0 is explicitly skipped; every point1..m-1 is checked. No fixedm/shift. -/
def candidateGuard (m shift : Nat) : Bool :=
  shiftGuard shift && (List.range m).all fun point =>
    decide (point = 0 ∨ (((point : Goldilocks) * (shift : Goldilocks)⁻¹)^domainSize ≠ 1))

def descriptorGuard (m shift : Nat) : Bool :=
  decide (0 < m ∧ m ≤ domainSize) && candidateGuard m shift

def point (shift : Nat) (index : Position) : Goldilocks :=
  (shift : Goldilocks) * radix2Root ^ index.val

theorem accepted_shift_nonzero (shift : Nat) (accepted : shiftGuard shift = true) :
    (shift : Goldilocks) ≠ 0 := by
  have guards : shift ≠ 0 ∧ shift < modulus := by simpa [shiftGuard] using accepted
  intro zero
  have values := congrArg ZMod.val zero
  change shift % modulus = 0 at values
  rw [Nat.mod_eq_of_lt guards.2] at values
  exact guards.1 values

theorem guarded_point_injective (shift : Nat) (accepted : shiftGuard shift = true) :
    Function.Injective (point shift) := by
  intro left right same
  have powers : radix2Root ^ left.val = radix2Root ^ right.val :=
    mul_left_cancel₀ (accepted_shift_nonzero shift accepted) same
  have finiteOrder : IsOfFinOrder radix2Root := isOfFinOrder_iff_pow_eq_one.mpr
    ⟨domainSize, by simp [domainSize], radix2_root_pow_domain⟩
  have remainders := (finiteOrder.pow_inj_mod (n := left.val) (m := right.val)).mp powers
  rw [radix2_root_order, Nat.mod_eq_of_lt left.isLt, Nat.mod_eq_of_lt right.isLt] at remainders
  exact Fin.ext remainders

theorem descriptor_point_injective (m shift : Nat) (accepted : descriptorGuard m shift = true) :
    Function.Injective (point shift) := by
  have guard : shiftGuard shift = true := by
    have checks : (0 < m ∧ m ≤ domainSize) ∧ shiftGuard shift = true ∧
        (List.range m).all (fun point => decide (point = 0 ∨
          (((point : Goldilocks) * (shift : Goldilocks)⁻¹)^domainSize ≠ 1))) = true := by
      simpa only [descriptorGuard, candidateGuard, Bool.and_eq_true, decide_eq_true_eq] using accepted
    exact checks.2.1
  exact guarded_point_injective shift guard

/-- Exact adjacent increasing check; empty and singleton lists pass. -/
def adjacentIncreasing : List Nat → Bool
  | [] => true
  | [_] => true
  | first :: second :: rest => decide (first < second) && adjacentIncreasing (second :: rest)

theorem adjacent_isChain (values : List Nat) (accepted : adjacentIncreasing values = true) :
    values.IsChain (· < ·) := by
  induction values with
  | nil => simp
  | cons first rest ih =>
      cases rest with
      | nil => simp
      | cons second rest =>
          have checks : first < second ∧ adjacentIncreasing (second :: rest) = true := by
            simpa only [adjacentIncreasing, Bool.and_eq_true, decide_eq_true_eq] using accepted
          exact List.isChain_cons_cons.mpr ⟨checks.1, ih checks.2⟩

theorem adjacent_pairwise (values : List Nat) (accepted : adjacentIncreasing values = true) :
    values.Pairwise (· < ·) :=
  List.isChain_iff_pairwise.mp (adjacent_isChain values accepted)

/-- Count is intrinsic to the typed38/58 wire and range intrinsic to FinN.
This models the adjacent strict-order part; Rust list-length/refinement joins
are not assumed by the typed constructor or proved here. -/
def wireIndexGuard {branch : Branch} (wire : WireFields branch Position) : Bool :=
  adjacentIncreasing (List.ofFn fun index => (wire.positions index).val)

theorem guarded_positions_injective {branch : Branch} (wire : WireFields branch Position)
    (accepted : wireIndexGuard wire = true) : Function.Injective wire.positions := by
  have ordered := List.pairwise_ofFn.mp (adjacent_pairwise _ accepted)
  intro left right same
  rcases lt_trichotomy left right with less | equal | greater
  · have strict := ordered less
    rw [same] at strict
    exact False.elim (Nat.lt_irrefl _ strict)
  · exact equal
  · have strict := ordered greater
    rw [same] at strict
    exact False.elim (Nat.lt_irrefl _ strict)

theorem guarded_sampled_points_injective {branch : Branch} (wire : WireFields branch Position)
    (shift : Nat) (shiftAccepted : shiftGuard shift = true) (indicesAccepted : wireIndexGuard wire = true) :
    Function.Injective (fun index => point shift (wire.positions index)) :=
  (guarded_point_injective shift shiftAccepted).comp (guarded_positions_injective wire indicesAccepted)

theorem descriptor_sampled_points_injective {branch : Branch} (wire : WireFields branch Position)
    (m shift : Nat) (descriptorAccepted : descriptorGuard m shift = true)
    (indicesAccepted : wireIndexGuard wire = true) :
    Function.Injective (fun index => point shift (wire.positions index)) :=
  (descriptor_point_injective m shift descriptorAccepted).comp (guarded_positions_injective wire indicesAccepted)

end HegemonCrypto.NativeLaunchGuardedPointGeometry
