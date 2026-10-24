import HegemonCrypto.NativeLaunchGuardedPointGeometry

/-! Source-shaped candidate-loop and bounded first-success selector model.
No fixed shift certificate, enumeration or search-existence assertion is used.
Rust arithmetic/byte refinement and launch authorization remain open. -/
set_option autoImplicit false
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000
namespace HegemonCrypto.NativeLaunchGuardedCosetSelection
open SmallWood SmallWood.V8Smz9DisjointCoset NativeLaunchGuardedPointGeometry

theorem candidate_shift_guard (m shift : Nat) (accepted : candidateGuard m shift = true) :
    shiftGuard shift = true := by
  have checks : shiftGuard shift = true ∧ (List.range m).all (fun x =>
      decide (x = 0 ∨ (((x : Goldilocks) * (shift : Goldilocks)⁻¹)^domainSize ≠ 1))) = true := by
    simpa only [candidateGuard, Bool.and_eq_true] using accepted
  exact checks.1

theorem candidate_coordinate_check (m shift : Nat) (accepted : candidateGuard m shift = true)
    (coordinate : Fin m) : coordinate.val = 0 ∨
      (((coordinate.val : Goldilocks) * (shift : Goldilocks)⁻¹)^domainSize ≠ 1) := by
  have checks : shiftGuard shift = true ∧ (List.range m).all (fun x =>
      decide (x = 0 ∨ (((x : Goldilocks) * (shift : Goldilocks)⁻¹)^domainSize ≠ 1))) = true := by
    simpa only [candidateGuard, Bool.and_eq_true] using accepted
  have each := List.all_eq_true.mp checks.2 coordinate.val (List.mem_range.mpr coordinate.isLt)
  exact of_decide_eq_true each

theorem root_power_nonzero (index : Position) : radix2Root ^ index.val ≠ 0 := by
  have rootNonzero : radix2Root ≠ 0 := by
    intro zero
    have rootOne := radix2_root_pow_domain
    rw [zero, zero_pow (by simp [domainSize])] at rootOne
    exact zero_ne_one rootOne
  exact pow_ne_zero _ rootNonzero

theorem accepted_point_nonzero (m shift : Nat) (accepted : candidateGuard m shift = true)
    (index : Position) : point shift index ≠ 0 :=
  mul_ne_zero (accepted_shift_nonzero shift (candidate_shift_guard m shift accepted))
    (root_power_nonzero index)

theorem normalized_point_power (m shift : Nat) (accepted : candidateGuard m shift = true)
    (index : Position) : (point shift index * (shift : Goldilocks)⁻¹)^domainSize = 1 := by
  have nonzero := accepted_shift_nonzero shift (candidate_shift_guard m shift accepted)
  have normalize : point shift index * (shift : Goldilocks)⁻¹ = radix2Root ^ index.val := by
    rw [point, mul_right_comm (shift : Goldilocks) (radix2Root ^ index.val)
      ((shift : Goldilocks)⁻¹), mul_inv_cancel₀ nonzero, one_mul]
  rw [normalize, ← pow_mul, Nat.mul_comm index.val domainSize, pow_mul,
    radix2_root_pow_domain, one_pow]

theorem candidate_interpolation_disjoint (m shift : Nat)
    (accepted : candidateGuard m shift = true) (coordinate : Fin m) (index : Position) :
    (coordinate.val : Goldilocks) ≠ point shift index := by
  intro same
  rcases candidate_coordinate_check m shift accepted coordinate with zero | checked
  · have pointZero : point shift index = 0 := by simpa [zero] using same.symm
    exact accepted_point_nonzero m shift accepted index pointZero
  · rw [same] at checked
    exact checked (normalized_point_power m shift accepted index)

theorem descriptor_interpolation_disjoint (m shift : Nat)
    (accepted : descriptorGuard m shift = true) (coordinate : Fin m) (index : Position) :
    (coordinate.val : Goldilocks) ≠ point shift index := by
  have checks : decide (0 < m ∧ m ≤ domainSize) = true ∧ candidateGuard m shift = true := by
    simpa only [descriptorGuard, Bool.and_eq_true] using accepted
  exact candidate_interpolation_disjoint m shift checks.2 coordinate index

/-- Ordered offsets are precisely 0..4095. Successful output is the first
accepted offset, not an asserted witness for search success. -/
def selectedOffset (m : Nat) : Option Nat :=
  (List.range 4096).find? (fun offset => candidateGuard m (m + offset))

def selectedShift (m : Nat) : Option Nat := (selectedOffset m).map (m + ·)

def checkedAddU64 (start offset : Nat) : Option Nat :=
  if start + offset < 2^64 then some (start + offset) else none

theorem selected_offset_bounds (m offset : Nat) (selected : selectedOffset m = some offset) :
    offset < 4096 := List.mem_range.mp (List.mem_of_find?_eq_some selected)

theorem selected_offset_guard (m offset : Nat) (selected : selectedOffset m = some offset) :
    candidateGuard m (m + offset) = true :=
  List.find?_some (p := fun offset => candidateGuard m (m + offset)) selected

/-- Every earlier list entry failed; the selected entry is first in range order. -/
theorem selected_offset_first (m offset : Nat) (selected : selectedOffset m = some offset) :
    ∃ before after, List.range 4096 = before ++ offset :: after ∧
      ∀ earlier ∈ before, candidateGuard m (m + earlier) = false := by
  have result := List.find?_eq_some_iff_append.mp selected
  rcases result.2 with ⟨before, after, split, failed⟩
  exact ⟨before, after, split, by simpa using failed⟩

theorem checked_add_safe (m offset : Nat) (geometry : 0 < m ∧ m ≤ domainSize)
    (bounded : offset < 4096) : checkedAddU64 m offset = some (m + offset) := by
  have bound : m + offset < 2^64 := by
    have maxM : m ≤ 8388608 := by simpa [domainSize] using geometry.2
    omega
  rw [checkedAddU64, if_pos bound]

theorem selected_shift_witness (m shift : Nat) (selected : selectedShift m = some shift) :
    ∃ offset, selectedOffset m = some offset ∧ m + offset = shift := by
  exact Option.map_eq_some_iff.mp selected

theorem selected_shift_disjoint (m shift : Nat) (selected : selectedShift m = some shift)
    (coordinate : Fin m) (index : Position) : (coordinate.val : Goldilocks) ≠ point shift index := by
  rcases selected_shift_witness m shift selected with ⟨offset, found, rfl⟩
  exact candidate_interpolation_disjoint m (m + offset) (selected_offset_guard m offset found)
    coordinate index

theorem selected_shift_checked_add (m shift : Nat) (geometry : 0 < m ∧ m ≤ domainSize)
    (selected : selectedShift m = some shift) :
    ∃ offset, offset < 4096 ∧ checkedAddU64 m offset = some shift := by
  rcases selected_shift_witness m shift selected with ⟨offset, found, rfl⟩
  have bound := selected_offset_bounds m offset found
  exact ⟨offset, bound, checked_add_safe m offset geometry bound⟩

end HegemonCrypto.NativeLaunchGuardedCosetSelection
