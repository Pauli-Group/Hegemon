import Hegemon.Transaction.SmallWoodProductionConstraintModel
import Mathlib.Data.ZMod.Basic

/-!
# Goldilocks residue-ring bridge

The production SmallWood evaluator stores Goldilocks elements as natural-number representatives.
This module supplies the residue ring used by deterministic CCS compilation. The protocol layer
must separately provide a compact primality certificate before using field-only theorems.
-/

namespace HegemonCrypto.SmallWood

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-- The residue ring used by the production SmallWood constraint system. -/
abbrev Goldilocks := ZMod goldilocksModulus

instance goldilocksNeZero : NeZero goldilocksModulus :=
  ⟨by decide⟩

/-- Embed a production natural-number representative in the Goldilocks field. -/
def toGoldilocks (value : Nat) : Goldilocks := value

/-- Return the unique canonical natural-number representative of a Goldilocks element. -/
def fromGoldilocks (value : Goldilocks) : Nat := value.val

theorem fromGoldilocks_lt (value : Goldilocks) :
    fromGoldilocks value < goldilocksModulus := by
  exact value.val_lt

theorem toGoldilocks_fromGoldilocks (value : Goldilocks) :
    toGoldilocks (fromGoldilocks value) = value := by
  exact ZMod.natCast_zmod_val value

theorem toGoldilocks_fieldValue (value : Nat) :
    toGoldilocks (fieldValue value) = toGoldilocks value := by
  simp [toGoldilocks, fieldValue]

theorem toGoldilocks_fieldAdd (left right : Nat) :
    toGoldilocks (fieldAdd left right) =
      toGoldilocks left + toGoldilocks right := by
  simp [toGoldilocks, fieldAdd]

theorem toGoldilocks_fieldMul (left right : Nat) :
    toGoldilocks (fieldMul left right) =
      toGoldilocks left * toGoldilocks right := by
  simp [toGoldilocks, fieldMul]

theorem toGoldilocks_fieldSub (left right : Nat) :
    toGoldilocks (fieldSub left right) =
      toGoldilocks left - toGoldilocks right := by
  change
    toGoldilocks
        (fieldValue (left + goldilocksModulus - right % goldilocksModulus)) = _
  rw [toGoldilocks_fieldValue]
  have hle : right % goldilocksModulus ≤ left + goldilocksModulus := by
    have hlt := Nat.mod_lt right (by decide : 0 < goldilocksModulus)
    exact hlt.le.trans (Nat.le_add_left goldilocksModulus left)
  change
    ((left + goldilocksModulus - right % goldilocksModulus : Nat) : Goldilocks) = _
  rw [Nat.cast_sub hle]
  simp [toGoldilocks]

theorem toGoldilocks_fieldNeg (value : Nat) :
    toGoldilocks (fieldNeg value) = -toGoldilocks value := by
  rw [fieldNeg, toGoldilocks_fieldSub]
  simp [toGoldilocks]

theorem fromGoldilocks_toGoldilocks (value : Nat) :
    fromGoldilocks (toGoldilocks value) = fieldValue value := by
  simp [fromGoldilocks, toGoldilocks, fieldValue, ZMod.val_natCast]

end HegemonCrypto.SmallWood
