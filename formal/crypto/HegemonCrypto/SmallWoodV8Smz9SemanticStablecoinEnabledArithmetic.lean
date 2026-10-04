import HegemonCrypto.SmallWoodV8Smz9SemanticDenseRange

/-! Small Goldilocks cast identity isolated from the enabled-stablecoin proof unit. -/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled

open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldSub fieldModulus)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem field_sub_zero_sub_one_cast (value : Nat) :
    ((fieldSub 0 (fieldSub value 1) : Nat) : F) = -((value : F) - 1) := by
  rw [field_sub_cast 0 _ (by
    have : fieldSub value 1 < fieldModulus := Nat.mod_lt _ (by decide)
    omega)]
  rw [field_sub_cast _ 1 (by
    change 1 ≤ _ + 18446744069414584321
    omega)]
  simp

end HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
