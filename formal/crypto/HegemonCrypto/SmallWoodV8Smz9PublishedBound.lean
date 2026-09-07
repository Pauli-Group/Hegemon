import HegemonCrypto.SmallWoodV8Smz9QromAccounting
import Mathlib.Data.Nat.Choose.Bounds

/-!
# The published DECS support-union certificate is vacuous for current SMZ9

SmallWood ePrint 2025/1085, revision 20260213:134127, Theorem 1 and Equation 14
charge `choose(N,d_decs+2)/p^eta` even for uniform challenge matrices. This module
substitutes the current source-owned SMZ9 parameters and proves that this expression
is greater than one. It is a no-go for that published upper-bound certificate, not
a lower bound on an adversary's success probability or a forgery of SMZ9.

The proof uses elementary factorial inequalities, not a floating logarithm or
evaluation of the enormous binomial coefficient. No new security assumption is added.
-/

namespace HegemonCrypto.SmallWood.V8Smz9PublishedBound

open V8Smz9QromAccounting

set_option exponentiation.threshold 8192
set_option maxRecDepth 100000

def publishedDegreeEnforcementBound : Rat :=
  (Nat.choose decsDomainSize (decsPolynomialDegree + 2) : Rat) /
    goldilocksOrder ^ decsEta

private theorem pow_le_choose_of_mul_le (n k base : Nat)
    (lowerBase : base * k ≤ n + 1 - k) : base ^ k ≤ Nat.choose n k := by
  have lowerFactorial :
      k.factorial * base ^ k ≤ n.descFactorial k := by
    calc
      k.factorial * base ^ k ≤ k ^ k * base ^ k :=
        Nat.mul_le_mul_right _ (Nat.factorial_le_pow k)
      _ = (base * k) ^ k := by
        rw [Nat.mul_pow]
        exact Nat.mul_comm _ _
      _ ≤ (n + 1 - k) ^ k := Nat.pow_le_pow_left lowerBase k
      _ ≤ n.descFactorial k := Nat.pow_sub_le_descFactorial _ _
  rw [Nat.descFactorial_eq_factorial_mul_choose] at lowerFactorial
  exact Nat.le_of_mul_le_mul_left lowerFactorial (Nat.factorial_pos k)

theorem published_support_family_has_at_least_5446_bits :
    2 ^ 5446 ≤ Nat.choose (2 ^ 23) 389 := by
  have bound := pow_le_choose_of_mul_le (2 ^ 23) 389 (2 ^ 14) (by decide)
  rw [← Nat.pow_mul] at bound
  exact bound

theorem published_degree_enforcement_bound_is_vacuous :
    1 < publishedDegreeEnforcementBound := by
  have modulusBound : goldilocksOrder < 2 ^ 64 := by
    norm_num [goldilocksOrder, Hegemon.Transaction.Poseidon2Width16Kernel.fieldModulus,
      Hegemon.Transaction.NoteCommitmentInputs.fieldModulus]
  have denominatorBound : goldilocksOrder ^ 5 < 2 ^ 320 := by
    calc
      goldilocksOrder ^ 5 < (2 ^ 64) ^ 5 := Nat.pow_lt_pow_left modulusBound (by decide)
      _ = 2 ^ 320 := by rw [← Nat.pow_mul]
  have strict : goldilocksOrder ^ 5 < Nat.choose (2 ^ 23) 389 := by
    exact denominatorBound.trans_le
      ((Nat.pow_le_pow_right (by decide : 0 < 2) (by decide : 320 ≤ 5446)).trans
        published_support_family_has_at_least_5446_bits)
  have positive : (0 : Rat) < goldilocksOrder ^ 5 := by
    norm_num [goldilocksOrder, Hegemon.Transaction.Poseidon2Width16Kernel.fieldModulus,
      Hegemon.Transaction.NoteCommitmentInputs.fieldModulus]
  unfold publishedDegreeEnforcementBound
  change 1 < (Nat.choose (2 ^ 23) 389 : Rat) / goldilocksOrder ^ 5
  apply (lt_div_iff₀ positive).mpr
  simpa only [one_mul] using (show (goldilocksOrder ^ 5 : Rat) < Nat.choose (2 ^ 23) 389 by
    exact_mod_cast strict)

end HegemonCrypto.SmallWood.V8Smz9PublishedBound
