import HegemonCrypto.SmallWoodV8Smz9SemanticDecoder

namespace HegemonCrypto.SmallWood.V8Smz9PositionBits

open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated

set_option autoImplicit false
set_option Elab.async false

theorem binary_natural_sum_bit (digits : Nat → Nat) (count : Nat)
    (bounds : ∀ index, index < count → digits index ≤ 1)
    {bit : Nat} (bitBound : bit < count) :
    (((List.range count).map (fun index => 2 ^ index * digits index)).sum /
      2 ^ bit) % 2 = digits bit := by
  induction count with
  | zero => omega
  | succ count ih =>
      have priorBounds : ∀ index, index < count → digits index ≤ 1 := by
        intro index bound
        exact bounds index (by omega)
      simp only [List.range_succ, List.map_append, List.sum_append,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, Nat.add_zero]
      by_cases top : bit = count
      · subst bit
        rw [Nat.add_mul_div_left _ _ (by positivity),
          Nat.div_eq_of_lt (binary_natural_sum_bound digits count priorBounds)]
        simp only [Nat.zero_add]
        exact Nat.mod_eq_of_lt (by have := bounds count (by omega); omega)
      · have lower : bit < count := by omega
        have power : 2 ^ count = 2 ^ bit * (2 * 2 ^ (count - bit - 1)) := by
          rw [← pow_succ', ← pow_add]
          congr 1
          omega
        rw [power, Nat.mul_assoc, Nat.add_mul_div_left _ _ (by positivity)]
        rw [Nat.mul_assoc, Nat.add_mul_mod_self_left]
        exact ih priorBounds lower

theorem accepted_project_position_bit {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {input bit : Nat} (inputBound : input < 2) (bitBound : bit < 32) :
    (projectPosition packed input / 2 ^ bit) % 2 = directionWord packed input bit := by
  apply binary_natural_sum_bit _ 32 _ bitBound
  intro index bound
  rcases accepted_direction_boolean accepted inputBound bound with zero | one <;> omega


end HegemonCrypto.SmallWood.V8Smz9PositionBits
