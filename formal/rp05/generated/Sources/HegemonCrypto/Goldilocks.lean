import Hegemon.Transaction.SmallWoodProductionConstraintModel
import Mathlib.Data.ZMod.Basic
import Mathlib.NumberTheory.LucasPrimality
import Mathlib.Tactic.NormNum.Prime
import Mathlib.Tactic.ReduceModChar

/-!
# Goldilocks residue-ring bridge

The production SmallWood evaluator stores Goldilocks elements as natural-number representatives.
This module supplies the residue field used by deterministic CCS compilation and a compact Lucas
primality certificate for its modulus.
-/

namespace HegemonCrypto.SmallWood

open Hegemon.Transaction.SmallWoodProductionConstraintRefinement

/-- The residue ring used by the production SmallWood constraint system. -/
abbrev Goldilocks := ZMod goldilocksModulus

instance goldilocksNeZero : NeZero goldilocksModulus :=
  ⟨by decide⟩

private theorem prime_divisor_goldilocks_sub_one
    {q : Nat}
    (qPrime : q.Prime)
    (divides : q ∣ goldilocksModulus - 1) :
    q = 2 ∨ q = 3 ∨ q = 5 ∨ q = 17 ∨ q = 257 ∨ q = 65537 := by
  have factorization :
      goldilocksModulus - 1 =
        2 ^ 32 * (3 * (5 * (17 * (257 * 65537)))) := by
    decide
  rw [factorization] at divides
  rcases qPrime.dvd_mul.mp divides with powerOfTwo | remaining
  · left
    exact (Nat.prime_dvd_prime_iff_eq qPrime Nat.prime_two).mp
      (qPrime.dvd_of_dvd_pow powerOfTwo)
  · right
    rcases qPrime.dvd_mul.mp remaining with dividesThree | remaining
    · left
      exact (Nat.prime_dvd_prime_iff_eq qPrime (by norm_num)).mp dividesThree
    · right
      rcases qPrime.dvd_mul.mp remaining with dividesFive | remaining
      · left
        exact (Nat.prime_dvd_prime_iff_eq qPrime (by norm_num)).mp dividesFive
      · right
        rcases qPrime.dvd_mul.mp remaining with dividesSeventeen | remaining
        · left
          exact (Nat.prime_dvd_prime_iff_eq qPrime (by norm_num)).mp dividesSeventeen
        · right
          rcases qPrime.dvd_mul.mp remaining with divides257 | divides65537
          · left
            exact (Nat.prime_dvd_prime_iff_eq qPrime (by norm_num)).mp divides257
          · right
            exact (Nat.prime_dvd_prime_iff_eq qPrime (by norm_num)).mp divides65537

private theorem seven_full_order :
    (7 : ZMod goldilocksModulus) ^ (goldilocksModulus - 1) = 1 := by
  have checked :
      (7 : ZMod 18446744069414584321) ^ 18446744069414584320 = 1 := by
    reduce_mod_char
  change
    (7 : ZMod 18446744069414584321) ^ 18446744069414584320 = 1
  exact checked

private theorem seven_div_two_ne_one :
    (7 : ZMod goldilocksModulus) ^ ((goldilocksModulus - 1) / 2) ≠ 1 := by
  have checked :
      (7 : ZMod 18446744069414584321) ^ 9223372034707292160 ≠ 1 := by
    reduce_mod_char
    decide
  change
    (7 : ZMod 18446744069414584321) ^ 9223372034707292160 ≠ 1
  exact checked

private theorem seven_div_three_ne_one :
    (7 : ZMod goldilocksModulus) ^ ((goldilocksModulus - 1) / 3) ≠ 1 := by
  have checked :
      (7 : ZMod 18446744069414584321) ^ 6148914689804861440 ≠ 1 := by
    reduce_mod_char
    decide
  change
    (7 : ZMod 18446744069414584321) ^ 6148914689804861440 ≠ 1
  exact checked

private theorem seven_div_five_ne_one :
    (7 : ZMod goldilocksModulus) ^ ((goldilocksModulus - 1) / 5) ≠ 1 := by
  have checked :
      (7 : ZMod 18446744069414584321) ^ 3689348813882916864 ≠ 1 := by
    reduce_mod_char
    decide
  change
    (7 : ZMod 18446744069414584321) ^ 3689348813882916864 ≠ 1
  exact checked

private theorem seven_div_seventeen_ne_one :
    (7 : ZMod goldilocksModulus) ^ ((goldilocksModulus - 1) / 17) ≠ 1 := by
  have checked :
      (7 : ZMod 18446744069414584321) ^ 1085102592318504960 ≠ 1 := by
    reduce_mod_char
    decide
  change
    (7 : ZMod 18446744069414584321) ^ 1085102592318504960 ≠ 1
  exact checked

private theorem seven_div_257_ne_one :
    (7 : ZMod goldilocksModulus) ^ ((goldilocksModulus - 1) / 257) ≠ 1 := by
  have checked :
      (7 : ZMod 18446744069414584321) ^ 71777214277877760 ≠ 1 := by
    reduce_mod_char
    decide
  change
    (7 : ZMod 18446744069414584321) ^ 71777214277877760 ≠ 1
  exact checked

private theorem seven_div_65537_ne_one :
    (7 : ZMod goldilocksModulus) ^ ((goldilocksModulus - 1) / 65537) ≠ 1 := by
  have checked :
      (7 : ZMod 18446744069414584321) ^ 281470681743360 ≠ 1 := by
    reduce_mod_char
    decide
  change
    (7 : ZMod 18446744069414584321) ^ 281470681743360 ≠ 1
  exact checked

/-- Kernel-checked Lucas certificate for the Goldilocks modulus. -/
theorem goldilocks_prime : Nat.Prime goldilocksModulus := by
  apply lucas_primality goldilocksModulus (7 : ZMod goldilocksModulus)
    seven_full_order
  intro q qPrime divides
  rcases prime_divisor_goldilocks_sub_one qPrime divides with
    rfl | rfl | rfl | rfl | rfl | rfl
  · exact seven_div_two_ne_one
  · exact seven_div_three_ne_one
  · exact seven_div_five_ne_one
  · exact seven_div_seventeen_ne_one
  · exact seven_div_257_ne_one
  · exact seven_div_65537_ne_one

instance goldilocksPrimeFact : Fact (Nat.Prime goldilocksModulus) :=
  ⟨goldilocks_prime⟩

/-- Embed a production natural-number representative in the Goldilocks field. -/
def toGoldilocks (value : Nat) : Goldilocks := value

/-- Return the unique canonical natural-number representative of a Goldilocks element. -/
def fromGoldilocks (value : Goldilocks) : Nat := value.val

/-- The concrete Goldilocks field has exactly its production modulus many elements. -/
theorem goldilocks_card :
    Fintype.card Goldilocks = goldilocksModulus := by
  rw [ZMod.card]

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

/-- `fieldAdd` folding is exactly finite summation after embedding in Goldilocks. -/
theorem toGoldilocks_foldl_fieldAdd
    (values : List Nat)
    (initial : Nat) :
    toGoldilocks (values.foldl fieldAdd initial) =
      toGoldilocks initial + (values.map toGoldilocks).sum := by
  induction values generalizing initial with
  | nil => simp
  | cons value values inductionHypothesis =>
      simp only [List.foldl_cons, List.map_cons, List.sum_cons]
      rw [inductionHypothesis, toGoldilocks_fieldAdd]
      ring

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
