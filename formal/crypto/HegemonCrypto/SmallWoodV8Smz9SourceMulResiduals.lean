import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import HegemonCrypto.SmallWoodV8Smz9SourceTailCheckedSubtractions

namespace HegemonCrypto.SmallWood.V8Smz9SourceMulResiduals

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldAdd fieldMul fieldSub fieldNormalize)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem source_time_carry_recomposition (x y z : Nat) (sum : x + y + 1 = z) :
    x % limbBase + y % limbBase + 1 =
      z % limbBase + limbBase * sourceTimeCarry x y 1 ∧
    x / limbBase + y / limbBase + sourceTimeCarry x y 1 = z / limbBase := by
  have hx := Nat.mod_add_div x limbBase
  have hy := Nat.mod_add_div y limbBase
  have hz := Nat.mod_add_div z limbBase
  have hm := Nat.mod_add_div (x % limbBase + y % limbBase + 1) limbBase
  have mx := Nat.mod_lt x (by decide : 0 < limbBase)
  have my := Nat.mod_lt y (by decide : 0 < limbBase)
  have mz := Nat.mod_lt z (by decide : 0 < limbBase)
  have mm := Nat.mod_lt (x % limbBase + y % limbBase + 1) (by decide : 0 < limbBase)
  have modulo : z % limbBase = (x % limbBase + y % limbBase + 1) % limbBase := by
    rw [← sum]
    simp [Nat.add_mod]
  simp only [sourceTimeCarry, limbBase] at *
  constructor <;> omega

theorem field_sub_cast_normalized_right (left right : Nat) (bound : right < fieldModulus) :
    (fieldSub left right : F) = (left : F) - (right : F) :=
  field_sub_cast left right (by change right ≤ left + fieldModulus; omega)

theorem source_low_residual_zero (x y z : Nat) (sum : x + y + 1 = z) :
    (sourceLowResidual x y z (sourceTimeCarry x y 1) : F) = 0 := by
  have equation := congrArg (fun word : Nat => (word : F))
    (source_time_carry_recomposition x y z sum).1
  rw [sourceLowResidual, field_sub_cast_normalized_right _
    (fieldAdd (z % limbBase) (fieldMul limbBase (sourceTimeCarry x y 1)))
    (by exact Nat.mod_lt _ (by decide))]
  simp only [field_add_cast, field_mul_cast, Nat.cast_one]
  apply sub_eq_zero.mpr
  simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_one] using equation

theorem source_high_residual_zero (x y z : Nat) (sum : x + y + 1 = z)
    (zBound : z < fieldModulus) :
    (sourceHighResidual x y z (sourceTimeCarry x y 1) : F) = 0 := by
  have equation := congrArg (fun word : Nat => (word : F))
    (source_time_carry_recomposition x y z sum).2
  rw [sourceHighResidual, field_sub_cast_normalized_right _ _
    (lt_of_le_of_lt (Nat.div_le_self _ _) zBound)]
  simp only [field_add_cast]
  exact sub_eq_zero.mpr (by simpa only [Nat.cast_add] using equation)






end HegemonCrypto.SmallWood.V8Smz9SourceMulResiduals
