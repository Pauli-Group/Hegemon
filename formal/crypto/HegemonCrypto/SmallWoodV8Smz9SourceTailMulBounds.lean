import HegemonCrypto.SmallWoodV8Smz9SourceTailNumericInputs

namespace HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000

theorem carry_product_bound (left right : Nat) (leftBound : left < limbBase)
    (rightBound : right < limbBase) : left * right / limbBase ≤ limbBase - 2 := by
  have product := Nat.mul_le_mul (show left ≤ limbBase - 1 by omega)
    (show right ≤ limbBase - 1 by omega)
  have strict : (limbBase - 1) * (limbBase - 1) < (limbBase - 1) * limbBase := by decide
  have quotient : left * right / limbBase < limbBase - 1 :=
    (Nat.div_lt_iff_lt_mul (by decide : 0 < limbBase)).mpr (by omega)
  omega

theorem carry_product_add_bound (left right carry : Nat) (leftBound : left < limbBase)
    (rightBound : right < limbBase) (carryBound : carry ≤ limbBase - 2) :
    (left * right + carry) / limbBase ≤ limbBase - 2 := by
  have product := Nat.mul_le_mul (show left ≤ limbBase - 1 by omega)
    (show right ≤ limbBase - 1 by omega)
  have strict : (limbBase - 1) * (limbBase - 1) + (limbBase - 2) <
      (limbBase - 1) * limbBase := by decide
  have quotient : (left * right + carry) / limbBase < limbBase - 1 :=
    (Nat.div_lt_iff_lt_mul (by decide : 0 < limbBase)).mpr (by omega)
  omega

structure Mul3Bounds (limbs : SourceMul3) : Prop where
  x0 : limbs.x0 < limbBase
  x1 : limbs.x1 < 2 ^ 24
  p0 : limbs.p0 < limbBase
  p1 : limbs.p1 < limbBase
  p2 : limbs.p2 < 2 ^ 24
  c0 : limbs.c0 ≤ limbBase - 2
  out : ∀ index, limbs.out index < limbBase
  out3 : limbs.out 3 < 2 ^ 24
  c1 : limbs.c1 ≤ limbBase - 2
  c2 : limbs.c2 ≤ limbBase - 2

theorem source_mul3_bounds (x y z : Nat) (xBound : x < 2 ^ 56)
    (yBound : y < 2 ^ 32) (zBound : z < 2 ^ 32) : Mul3Bounds (sourceMul3 x y z) := by
  have x0 : x % limbBase < limbBase := Nat.mod_lt _ (by decide)
  have p0 : (x * y) % limbBase < limbBase := Nat.mod_lt _ (by decide)
  have p1 : (x * y / limbBase) % limbBase < limbBase := Nat.mod_lt _ (by decide)
  have firstBound : x * y < 2 ^ 88 := by
    have bound := Nat.mul_le_mul (show x ≤ 72057594037927935 by omega)
      (show y ≤ 4294967295 by omega)
    norm_num at bound ⊢
    omega
  have secondBound : x * y * z < 2 ^ 120 := by
    have bound := Nat.mul_le_mul (show x * y ≤ 309485009821345068724781055 by omega)
      (show z ≤ 4294967295 by omega)
    norm_num at bound ⊢
    omega
  have x1 : x / limbBase < 2 ^ 24 :=
    (Nat.div_lt_iff_lt_mul (by decide : 0 < limbBase)).mpr
      (by simpa only [show 2 ^ 24 * limbBase = 2 ^ 56 by decide] using xBound)
  have highFirst : x * y / limbBase ^ 2 < 2 ^ 24 :=
    (Nat.div_lt_iff_lt_mul (by decide : 0 < limbBase ^ 2)).mpr
      (by simpa only [show 2 ^ 24 * limbBase ^ 2 = 2 ^ 88 by decide] using firstBound)
  have highSecond : x * y * z / limbBase ^ 3 < 2 ^ 24 :=
    (Nat.div_lt_iff_lt_mul (by decide : 0 < limbBase ^ 3)).mpr
      (by simpa only [show 2 ^ 24 * limbBase ^ 3 = 2 ^ 120 by decide] using secondBound)
  have c0 := carry_product_bound (x % limbBase) y x0 yBound
  have c1 := carry_product_bound (x * y % limbBase) z p0 zBound
  have c2 := carry_product_add_bound ((x * y / limbBase) % limbBase) z
    ((x * y % limbBase) * z / limbBase) p1 zBound c1
  refine ⟨x0, x1, p0, p1, ?_, c0, ?_, ?_, c1, c2⟩
  · exact lt_of_le_of_lt (Nat.mod_le _ _) highFirst
  · intro index
    exact Nat.mod_lt _ (by decide)
  · exact lt_of_le_of_lt (Nat.mod_le _ _) highSecond

theorem zero_mul3_bounds : Mul3Bounds ({} : SourceMul3) := by
  refine ⟨by decide,by decide,by decide,by decide,by decide,by decide,?_,by decide,by decide,by decide⟩
  intro index
  change 0 < limbBase
  decide

theorem mul3_range_word_bound (limbs : SourceMul3) (bounds : Mul3Bounds limbs)
    (word : Nat) (member : word ∈ limbs.rangeValues) : word < limbBase := by
  obtain ⟨x0,x1,p0,p1,p2,c0,out,out3,c1,c2⟩ := bounds
  have o0 := out 0
  have o1 := out 1
  have o2 := out 2
  have o3 := out 3
  have high : 2 ^ 24 < limbBase := by decide
  simp only [SourceMul3.rangeValues, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> omega

def MulTupleCanonical (tuple : SourceMulTuple) : Prop :=
  tuple.a < fieldModulus ∧ tuple.b < fieldModulus ∧ tuple.c < fieldModulus

theorem mul3_lane_canonical (limbs : SourceMul3) (bounds : Mul3Bounds limbs)
    (y z : Nat) (yBound : y < limbBase) (zBound : z < limbBase) (lane : Nat) :
    MulTupleCanonical (sourceMul3Lane limbs y z lane) := by
  obtain ⟨x0,x1,p0,p1,p2,c0,out,out3,c1,c2⟩ := bounds
  have o0 := out 0
  have o1 := out 1
  have o2 := out 2
  unfold sourceMul3Lane MulTupleCanonical
  split <;> dsimp only <;> simp only [limbBase, fieldModulus] at * <;> constructor
  all_goals omega


end HegemonCrypto.SmallWood.V8Smz9SourceTailNumericBounds
