import Mathlib.Data.Real.Basic
import Mathlib.Tactic.NormNum

/-! Arithmetic accounting only. No primitive advantage bound, computational
reduction, Rust refinement or adaptive-context extraction is established here. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PrimitiveBudget

set_option autoImplicit false

def sixAdvantageSum (note merkle nullifier single accumulator mixed : ℝ) : ℝ :=
  note + merkle + nullifier + single + accumulator + mixed

/-- Sufficient aggregate budget for the six explicitly conditional terms.
The caller must separately justify the supplied primitive bounds. -/
theorem below_128_of_aggregate_budget
    (extraction note merkle nullifier single accumulator mixed : ℝ)
    (extractionBound : extraction < 1 / (2 : ℝ) ^ 130)
    (primitiveBudget : sixAdvantageSum note merkle nullifier single accumulator mixed
      ≤ 3 / (2 : ℝ) ^ 130) :
    extraction + sixAdvantageSum note merkle nullifier single accumulator mixed
      < 1 / (2 : ℝ) ^ 128 := by
  calc
    extraction + sixAdvantageSum note merkle nullifier single accumulator mixed
        < 1 / (2 : ℝ) ^ 130 +
          sixAdvantageSum note merkle nullifier single accumulator mixed :=
      add_lt_add_left extractionBound _
    _ ≤ 1 / (2 : ℝ) ^ 130 + 3 / (2 : ℝ) ^ 130 :=
      add_le_add_right primitiveBudget _
    _ = 1 / (2 : ℝ) ^ 128 := by norm_num

/-- One possible equal allocation; this proves arithmetic, not that any of
the six actual games has this advantage. -/
theorem six_individual_bounds_suffice
    (note merkle nullifier single accumulator mixed : ℝ)
    (noteBound : note ≤ 1 / (2 : ℝ) ^ 131)
    (merkleBound : merkle ≤ 1 / (2 : ℝ) ^ 131)
    (nullifierBound : nullifier ≤ 1 / (2 : ℝ) ^ 131)
    (singleBound : single ≤ 1 / (2 : ℝ) ^ 131)
    (accumulatorBound : accumulator ≤ 1 / (2 : ℝ) ^ 131)
    (mixedBound : mixed ≤ 1 / (2 : ℝ) ^ 131) :
    sixAdvantageSum note merkle nullifier single accumulator mixed
      ≤ 3 / (2 : ℝ) ^ 130 := by
  have all := add_le_add
    (add_le_add (add_le_add (add_le_add (add_le_add noteBound merkleBound)
      nullifierBound) singleBound) accumulatorBound) mixedBound
  unfold sixAdvantageSum
  calc
    note + merkle + nullifier + single + accumulator + mixed
        ≤ 1 / (2 : ℝ) ^ 131 + 1 / (2 : ℝ) ^ 131 + 1 / (2 : ℝ) ^ 131 +
          1 / (2 : ℝ) ^ 131 + 1 / (2 : ℝ) ^ 131 + 1 / (2 : ℝ) ^ 131 := all
    _ = 3 / (2 : ℝ) ^ 130 := by norm_num

end HegemonCrypto.SmallWood.SmzaRp05PrimitiveBudget
