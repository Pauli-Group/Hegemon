import HegemonCrypto.SmallWoodV8Smz9StableCounterEndpoint
import Mathlib.Tactic.Ring

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableDecimalEndpoint

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

def decimalBitSum (packed : List Nat) (start : Nat) : Nat :=
  packedWord packed start + 2 * packedWord packed (start+1) + 4 * packedWord packed (start+2) +
    8 * packedWord packed (start+3) + 16 * packedWord packed (start+4)

theorem accepted_decimal_bits_bound {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (start : Nat) (bound : start + 4 < 64) :
    decimalBitSum packed (42112 + start) < 32 := by
  have bit (i : Nat) (h : i < 5) : packedWord packed (42112 + start + i) ≤ 1 := by
    have b := accepted_stable_boolean accepted (lane := start + i) (by omega)
    rcases b with h | h <;> simp only [← Nat.add_assoc] at h <;> omega
  have b0 := bit 0 (by decide)
  have b1 := bit 1 (by decide)
  have b2 := bit 2 (by decide)
  have b3 := bit 3 (by decide)
  have b4 := bit 4 (by decide)
  simp only [Nat.add_zero] at b0
  simp only [decimalBitSum]
  omega

def stableDecimalAttempts : List CsrExecutableAttempt :=
  [attempt 20321 64 0 0 [(41454, 1), (42124, 158), (42125, 206), (42126, 159), (42127, 208), (42128, 210)] 0,
   attempt 20322 65 0 0 [(41454, 1), (42129, 1), (42130, 2), (42131, 128), (42132, 207), (42133, 209)] 417,
   attempt 20323 66 0 1 [(41455, 306), (42193, 321)] 0,
   attempt 20376 73 0 0 [(42240, 1)] 1,
   attempt 20377 73 1 0 [(42304, 1), (42124, 439)] 1,
   attempt 20378 73 2 0 [(42368, 1), (42189, 158)] 0,
   attempt 20379 73 3 0 [(42241, 1), (42189, 158)] 0,
   attempt 20380 73 4 0 [(42305, 1), (42125, 441)] 1,
   attempt 20381 73 5 0 [(42369, 1), (42190, 158)] 0,
   attempt 20382 73 6 0 [(42242, 1), (42190, 158)] 0,
   attempt 20383 73 7 0 [(42306, 1), (42126, 443)] 1,
   attempt 20384 73 8 0 [(42370, 1), (42191, 158)] 0,
   attempt 20385 73 9 0 [(42243, 1), (42191, 158)] 0,
   attempt 20386 73 10 0 [(42307, 1), (42127, 445)] 1,
   attempt 20387 73 11 0 [(42371, 1), (42192, 158)] 0,
   attempt 20388 73 12 0 [(42244, 1), (42192, 158)] 0,
   attempt 20389 73 13 0 [(42308, 1), (42128, 447)] 1,
   attempt 20390 73 14 0 [(42372, 1), (42193, 158)] 0]

theorem exact_stable_decimal_attempts : ∀ entry, entry ∈ stableDecimalAttempts →
    entry ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry =>
      entry.family == 64 || entry.family == 65 || entry.family == 66 || entry.family == 73) =
      stableDecimalAttempts := by decide
  intro entry member
  exact (List.mem_filter.mp (show entry ∈ exactCsrAttempts.filter (fun entry =>
    entry.family == 64 || entry.family == 65 || entry.family == 66 || entry.family == 73) by
      rw [checked]; exact member)).1

theorem accepted_decimal_power_identity {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (1 + 9 * packedWord packed 42124) * (1 + 99 * packedWord packed 42125) *
      (1 + 9999 * packedWord packed 42126) * (1 + 99999999 * packedWord packed 42127) *
      (1 + 9999999999999999 * packedWord packed 42128) = 10 ^ decimalBitSum packed 42124 := by
  have b0 := accepted_stable_boolean accepted (lane := 12) (by decide)
  have b1 := accepted_stable_boolean accepted (lane := 13) (by decide)
  have b2 := accepted_stable_boolean accepted (lane := 14) (by decide)
  have b3 := accepted_stable_boolean accepted (lane := 15) (by decide)
  have b4 := accepted_stable_boolean accepted (lane := 16) (by decide)
  rcases b0 with b0 | b0 <;> rcases b1 with b1 | b1 <;> rcases b2 with b2 | b2 <;>
    rcases b3 with b3 | b3 <;> rcases b4 with b4 | b4 <;>
    simp only [decimalBitSum, Nat.reduceAdd, b0, b1, b2, b3, b4] <;> norm_num

/-- The accepted five multiplication lanes compute the exact decimal exponent in the field. -/
theorem accepted_stable_decimal_field {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    (packedWord packed 41454 : F) = (decimalBitSum packed 42124 : F) ∧
    ((packedWord packed 41454 + decimalBitSum packed 42129 : Nat) : F) = 18 ∧
    (packedWord packed 41455 : F) = ((10 ^ decimalBitSum packed 42124 : Nat) : F) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have equations := evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated
  have natEquations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found
  have gate := stable_enabled_gate_value natEquations accepted.1 direction
  have v306 : (values.getD 306 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, gate]
  have v0 : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have v1 : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have v2 : (values.getD 2 0 : F) = 2 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 2 (.constant 2) (by decide)
  have v128 : (values.getD 128 0 : F) = 4 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 128 (.constant 4) (by decide)
  have v158 : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, v0, v1, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have v159 : (values.getD 159 0 : F) = -4 := by
    simpa only [expressionField, v0, v128, zero_sub] using equations 159 (.sub 0 128) (by decide)
  have v206 : (values.getD 206 0 : F) = -2 := by
    simpa only [expressionField, v0, v2, zero_sub] using equations 206 (.sub 0 2) (by decide)
  have v207 : (values.getD 207 0 : F) = 8 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 207 (.constant 8) (by decide)
  have v208 : (values.getD 208 0 : F) = -8 := by
    simpa only [expressionField, v0, v207, zero_sub] using equations 208 (.sub 0 207) (by decide)
  have v209 : (values.getD 209 0 : F) = 16 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 209 (.constant 16) (by decide)
  have v210 : (values.getD 210 0 : F) = -16 := by
    simpa only [expressionField, v0, v209, zero_sub] using equations 210 (.sub 0 209) (by decide)
  have v414 : (values.getD 414 0 : F) = 18 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 414 (.constant 18) (by decide)
  have v415 : (values.getD 415 0 : F) = 18 := by
    simpa only [expressionField, v306, v414, one_mul] using equations 415 (.mul 306 414) (by decide)
  have v416 : (values.getD 416 0 : F) = -18 := by
    simpa only [expressionField, v0, v415, zero_sub] using equations 416 (.sub 0 415) (by decide)
  have v417 : (values.getD 417 0 : F) = 18 := by
    simpa only [expressionField, v0, v416, zero_sub, neg_neg] using equations 417 (.sub 0 416) (by decide)
  have v321 : (values.getD 321 0 : F) = -1 := by
    simpa only [expressionField, v158, v306, mul_one] using equations 321 (.mul 158 306) (by decide)
  have v438 : (values.getD 438 0 : F) = 9 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 438 (.constant 9) (by decide)
  have v439 : (values.getD 439 0 : F) = -9 := by
    simpa only [expressionField, v0, v438, zero_sub] using equations 439 (.sub 0 438) (by decide)
  have v440 : (values.getD 440 0 : F) = 99 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 440 (.constant 99) (by decide)
  have v441 : (values.getD 441 0 : F) = -99 := by
    simpa only [expressionField, v0, v440, zero_sub] using equations 441 (.sub 0 440) (by decide)
  have v442 : (values.getD 442 0 : F) = 9999 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 442 (.constant 9999) (by decide)
  have v443 : (values.getD 443 0 : F) = -9999 := by
    simpa only [expressionField, v0, v442, zero_sub] using equations 443 (.sub 0 442) (by decide)
  have v444 : (values.getD 444 0 : F) = 99999999 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 444 (.constant 99999999) (by decide)
  have v445 : (values.getD 445 0 : F) = -99999999 := by
    simpa only [expressionField, v0, v444, zero_sub] using equations 445 (.sub 0 444) (by decide)
  have v446 : (values.getD 446 0 : F) = 9999999999999999 := by
    simpa only [expressionField, Nat.cast_ofNat] using equations 446 (.constant 9999999999999999) (by decide)
  have v447 : (values.getD 447 0 : F) = -9999999999999999 := by
    simpa only [expressionField, v0, v446, zero_sub] using equations 447 (.sub 0 446) (by decide)
  have e0 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20321 64 0 0 [(41454, 1), (42124, 158), (42125, 206), (42126, 159), (42127, 208), (42128, 210)] 0) (by decide)))
  have e1 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20322 65 0 0 [(41454, 1), (42129, 1), (42130, 2), (42131, 128), (42132, 207), (42133, 209)] 417) (by decide)))
  have e2 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20323 66 0 1 [(41455, 306), (42193, 321)] 0) (by decide)))
  have e3 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20376 73 0 0 [(42240, 1)] 1) (by decide)))
  have e4 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20377 73 1 0 [(42304, 1), (42124, 439)] 1) (by decide)))
  have e5 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20378 73 2 0 [(42368, 1), (42189, 158)] 0) (by decide)))
  have e6 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20379 73 3 0 [(42241, 1), (42189, 158)] 0) (by decide)))
  have e7 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20380 73 4 0 [(42305, 1), (42125, 441)] 1) (by decide)))
  have e8 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20381 73 5 0 [(42369, 1), (42190, 158)] 0) (by decide)))
  have e9 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20382 73 6 0 [(42242, 1), (42190, 158)] 0) (by decide)))
  have e10 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20383 73 7 0 [(42306, 1), (42126, 443)] 1) (by decide)))
  have e11 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20384 73 8 0 [(42370, 1), (42191, 158)] 0) (by decide)))
  have e12 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20385 73 9 0 [(42243, 1), (42191, 158)] 0) (by decide)))
  have e13 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20386 73 10 0 [(42307, 1), (42127, 445)] 1) (by decide)))
  have e14 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20387 73 11 0 [(42371, 1), (42192, 158)] 0) (by decide)))
  have e15 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20388 73 12 0 [(42244, 1), (42192, 158)] 0) (by decide)))
  have e16 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20389 73 13 0 [(42308, 1), (42128, 447)] 1) (by decide)))
  have e17 := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_decimal_attempts (attempt 20390 73 14 0 [(42372, 1), (42193, 158)] 0) (by decide)))
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    v1, v158, v206, v159, v208, v210, v0, v2, v128, v207, v209, v417, v306, v321, v439, v441, v443, v445, v447,
    one_mul, neg_one_mul, add_zero] at e0 e1 e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13 e14 e15 e16 e17
  have digits : (packedWord packed 41454 : F) = (decimalBitSum packed 42124 : F) := by
    simp only [packedWord, decimalBitSum, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat, Nat.reduceAdd]
    have eq := add_eq_zero_iff_eq_neg.mp e0
    rw [eq]
    ring
  have cap : ((packedWord packed 41454 + decimalBitSum packed 42129 : Nat) : F) = 18 := by
    simpa only [packedWord, decimalBitSum, Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat,
      Nat.reduceAdd, mul_one, add_assoc] using e1
  have scaleEq : (packedWord packed 41455 : F) = (packedWord packed 42193 : F) :=
    add_neg_eq_zero.mp e2
  have b0 : (packed.getD 42304 0 : F) = (1 + 9 * (packed.getD 42124 0 : F)) := by
    exact sub_eq_iff_eq_add.mp (by simpa only [sub_eq_add_neg, neg_mul] using e4)
  have c0 := add_neg_eq_zero.mp e5
  have mul0 := accepted_stable_mul_lane accepted (lane := 0) (by decide)
  simp only [packedWord, Nat.reduceAdd] at mul0
  rw [e3, b0, c0] at mul0
  have stage0 : (packed.getD 42189 0 : F) = (1 + 9 * (packed.getD 42124 0 : F)) := by
    simpa only [one_mul] using mul0.symm
  have a1 := add_neg_eq_zero.mp e6
  have b1 : (packed.getD 42305 0 : F) = (1 + 99 * (packed.getD 42125 0 : F)) := by
    exact sub_eq_iff_eq_add.mp (by simpa only [sub_eq_add_neg, neg_mul] using e7)
  have c1 := add_neg_eq_zero.mp e8
  have mul1 := accepted_stable_mul_lane accepted (lane := 1) (by decide)
  simp only [packedWord, Nat.reduceAdd] at mul1
  rw [a1, b1, c1, stage0] at mul1
  have stage1 : (packed.getD 42190 0 : F) = ((1 + 9 * (packed.getD 42124 0 : F)) * (1 + 99 * (packed.getD 42125 0 : F))) := by
    simpa only [one_mul] using mul1.symm
  have a2 := add_neg_eq_zero.mp e9
  have b2 : (packed.getD 42306 0 : F) = (1 + 9999 * (packed.getD 42126 0 : F)) := by
    exact sub_eq_iff_eq_add.mp (by simpa only [sub_eq_add_neg, neg_mul] using e10)
  have c2 := add_neg_eq_zero.mp e11
  have mul2 := accepted_stable_mul_lane accepted (lane := 2) (by decide)
  simp only [packedWord, Nat.reduceAdd] at mul2
  rw [a2, b2, c2, stage1] at mul2
  have stage2 : (packed.getD 42191 0 : F) = (((1 + 9 * (packed.getD 42124 0 : F)) * (1 + 99 * (packed.getD 42125 0 : F))) * (1 + 9999 * (packed.getD 42126 0 : F))) := by
    simpa only [one_mul] using mul2.symm
  have a3 := add_neg_eq_zero.mp e12
  have b3 : (packed.getD 42307 0 : F) = (1 + 99999999 * (packed.getD 42127 0 : F)) := by
    exact sub_eq_iff_eq_add.mp (by simpa only [sub_eq_add_neg, neg_mul] using e13)
  have c3 := add_neg_eq_zero.mp e14
  have mul3 := accepted_stable_mul_lane accepted (lane := 3) (by decide)
  simp only [packedWord, Nat.reduceAdd] at mul3
  rw [a3, b3, c3, stage2] at mul3
  have stage3 : (packed.getD 42192 0 : F) = ((((1 + 9 * (packed.getD 42124 0 : F)) * (1 + 99 * (packed.getD 42125 0 : F))) * (1 + 9999 * (packed.getD 42126 0 : F))) * (1 + 99999999 * (packed.getD 42127 0 : F))) := by
    simpa only [one_mul] using mul3.symm
  have a4 := add_neg_eq_zero.mp e15
  have b4 : (packed.getD 42308 0 : F) = (1 + 9999999999999999 * (packed.getD 42128 0 : F)) := by
    exact sub_eq_iff_eq_add.mp (by simpa only [sub_eq_add_neg, neg_mul] using e16)
  have c4 := add_neg_eq_zero.mp e17
  have mul4 := accepted_stable_mul_lane accepted (lane := 4) (by decide)
  simp only [packedWord, Nat.reduceAdd] at mul4
  rw [a4, b4, c4, stage3] at mul4
  have stage4 : (packed.getD 42193 0 : F) = (((((1 + 9 * (packed.getD 42124 0 : F)) * (1 + 99 * (packed.getD 42125 0 : F))) * (1 + 9999 * (packed.getD 42126 0 : F))) * (1 + 99999999 * (packed.getD 42127 0 : F))) * (1 + 9999999999999999 * (packed.getD 42128 0 : F))) := by
    simpa only [one_mul] using mul4.symm
  refine ⟨digits, cap, ?_⟩
  rw [scaleEq]
  have identity := congrArg (fun n : Nat => (n : F)) (accepted_decimal_power_identity accepted)
  simp only [Nat.cast_add, Nat.cast_mul, Nat.cast_one, Nat.cast_ofNat, packedWord] at identity
  exact stage4.trans identity

/-- Enabled decimal metadata has its exact bounded Nat meaning; field wrap is excluded. -/
theorem accepted_stable_decimal_scale {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    packedWord packed 41454 ≤ 18 ∧ packedWord packed 41455 = 10 ^ packedWord packed 41454 := by
  obtain ⟨digits, cap, scale⟩ := accepted_stable_decimal_field accepted direction
  have digitBound := accepted_decimal_bits_bound accepted 12 (by decide)
  have slackBound := accepted_decimal_bits_bound accepted 17 (by decide)
  change decimalBitSum packed 42124 < 32 at digitBound
  change decimalBitSum packed 42129 < 32 at slackBound
  have digitsNat : packedWord packed 41454 = decimalBitSum packed 42124 := by
    apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    · change _ < 18446744069414584321
      omega
    · exact digits
  have capNat : packedWord packed 41454 + decimalBitSum packed 42129 = 18 := by
    apply canonical_nat_cast_injective
    · change _ < 18446744069414584321
      omega
    · decide
    · exact cap
  have decimalBound : packedWord packed 41454 ≤ 18 := by omega
  refine ⟨decimalBound, ?_⟩
  apply canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
  · exact (Nat.pow_le_pow_right (by decide : 0 < 10) decimalBound).trans_lt (by decide)
  · simpa only [digitsNat] using scale


end HegemonCrypto.SmallWood.V8Smz9SemanticStableDecimalEndpoint
