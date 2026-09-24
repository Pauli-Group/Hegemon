import HegemonCrypto.SmallWoodV8Smz9SourceReplicatedRows

namespace HegemonCrypto.SmallWood.V8Smz9SourcePositionReconstruction
open HegemonCrypto.SmallWood.V8Smz9SourceReplicatedRows
set_option maxRecDepth 100000
set_option maxHeartbeats 1500000
set_option Elab.async false

def positionBitSum (value count : Nat) : Nat :=
  ((List.range count).map (fun bit => 2 ^ bit * positionBit value bit)).sum

theorem position_bit_sum_add_quotient (value count : Nat) :
    positionBitSum value count + 2 ^ count * (value / 2 ^ count) = value := by
  induction count with
  | zero => simp [positionBitSum]
  | succ count inductionHypothesis =>
    have division := Nat.div_add_mod (value / 2 ^ count) 2
    have nextDivision : value / 2 ^ (count + 1) = (value / 2 ^ count) / 2 := by
      rw [pow_succ,Nat.div_div_eq_div_mul]
    simp only [positionBitSum,List.range_succ,List.map_append,List.sum_append,
      List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,Nat.add_zero]
    change positionBitSum value count + 2 ^ count * positionBit value count +
      2 ^ (count + 1) * (value / 2 ^ (count + 1)) = value
    rw [nextDivision,pow_succ]
    have weighted := congrArg (fun term => 2 ^ count * term) division
    unfold positionBit at inductionHypothesis ⊢
    nlinarith [weighted]

theorem position_bits32_exact (value : Nat) (bound : value < 2 ^ 32) :
    ((List.range 32).map (fun bit => 2 ^ bit * positionBit value bit)).sum = value := by
  have reconstruction := position_bit_sum_add_quotient value 32
  rw [Nat.div_eq_of_lt bound,Nat.mul_zero,Nat.add_zero] at reconstruction
  exact reconstruction

end HegemonCrypto.SmallWood.V8Smz9SourcePositionReconstruction
