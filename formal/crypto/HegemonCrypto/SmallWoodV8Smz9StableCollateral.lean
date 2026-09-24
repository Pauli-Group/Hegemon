import HegemonCrypto.SmallWoodV8Smz9StableCounterEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

theorem carry_equation_nat {a b carry low high : Nat}
    (ha : a < 4294967296) (hb : b < 4294967296)
    (hc : carry < 4294967295) (hl : low < 4294967296)
    (hh : high < 4294967295)
    (eq : (a : F) * (b : F) + (carry : F) =
      (low : F) + (high : F) * 4294967296) :
    a * b + carry = low + high * 4294967296 := by
  have productBound := Nat.mul_le_mul
    (show a ≤ 4294967295 by omega) (show b ≤ 4294967295 by omega)
  have leftBound : a * b + carry < fieldModulus := by
    change _ < 18446744069414584321
    norm_num at productBound
    omega
  have rightBound : low + high * 4294967296 < fieldModulus := by
    change _ < 18446744069414584321
    omega
  apply canonical_nat_cast_injective leftBound rightBound
  simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat] using eq

theorem product_two_stage {x0 x1 multiplier scale p0 p1 p2 c0 c1 c2
    y0 y1 y2 y3 : Nat}
    (e0 : x0 * multiplier = p0 + c0 * 4294967296)
    (e1 : x1 * multiplier + c0 = p1 + p2 * 4294967296)
    (e2 : p0 * scale = y0 + c1 * 4294967296)
    (e3 : p1 * scale + c1 = y1 + c2 * 4294967296)
    (e4 : p2 * scale + c2 = y2 + y3 * 4294967296) :
    (x0 + x1 * 4294967296) * multiplier * scale =
      y0 + y1 * 4294967296 + y2 * 18446744073709551616 +
        y3 * 79228162514264337593543950336 := by
  have first : (x0 + x1 * 4294967296) * multiplier =
      p0 + p1 * 4294967296 + p2 * 18446744073709551616 := by
    nlinarith [e0, e1]
  rw [first]
  nlinarith [e2, e3, e4]

theorem four_limb_subtraction {l0 l1 l2 l3 r0 r1 r2 r3
    d0 d1 d2 d3 b0 b1 b2 : Nat}
    (e0 : l0 + b0 * 4294967296 = r0 + d0)
    (e1 : l1 + b1 * 4294967296 = r1 + b0 + d1)
    (e2 : l2 + b2 * 4294967296 = r2 + b1 + d2)
    (e3 : l3 = r3 + b2 + d3) :
    r0 + r1 * 4294967296 + r2 * 18446744073709551616 +
      r3 * 79228162514264337593543950336 ≤
    l0 + l1 * 4294967296 + l2 * 18446744073709551616 +
      l3 * 79228162514264337593543950336 := by
  omega

def highLimbSpecs : List (Nat × Nat) :=
  [(19, 1002), (22, 1050), (27, 1130), (31, 1194), (34, 1242), (39, 1322)]

def highPaddingAttempt (slot digit : Nat) : CsrExecutableAttempt :=
  attempt (20296 + 4 * slot + digit) 62 (4 * slot + digit) 0
    [(42432 + (highLimbSpecs.getD slot (0, 0)).2 + 12 + digit, 1)] 0

theorem exact_high_padding_attempts : ∀ slot, slot < 6 → ∀ digit, digit < 4 →
    highPaddingAttempt slot digit ∈ exactCsrAttempts := by
  have cert : exactCsrAttempts.filter (fun entry => entry.family == 62) =
      (List.range 6).flatMap (fun slot => (List.range 4).map (highPaddingAttempt slot)) := by decide
  intro slot hs digit hd
  have member : highPaddingAttempt slot digit ∈ exactCsrAttempts.filter
      (fun entry => entry.family == 62) := by
    rw [cert]
    exact List.mem_flatMap.mpr ⟨slot, List.mem_range.mpr hs,
      List.mem_map.mpr ⟨digit, List.mem_range.mpr hd, rfl⟩⟩
  exact (List.mem_filter.mp member).1

theorem accepted_high_digit_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {slot digit : Nat} (hs : slot < 6) (hd : digit < 4) :
    packedWord packed
      (42432 + (highLimbSpecs.getD slot (0, 0)).2 + 12 + digit) = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  have zero := equations 0 (.constant 0) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at one zero
  have eq := accepted_csr_attempt_field_equality
    (attempts _ (exact_high_padding_attempts slot hs digit hd))
  simp only [highPaddingAttempt, attempt, csrFieldSum, List.map_cons,
    List.map_nil, List.sum_cons, List.sum_nil, one, zero, one_mul, add_zero] at eq
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
    (by simpa only [packedWord, Nat.cast_zero] using eq)

theorem radix_four_drop_high {digits : Nat → Nat}
    (zero : ∀ d, 12 ≤ d → d < 16 → digits d = 0) :
    radixFourSum digits 16 = radixFourSum digits 12 := by
  have split : List.range 16 = List.range 12 ++ [12, 13, 14, 15] := by decide
  simp [radixFourSum, split, zero 12 (by decide) (by decide),
    zero 13 (by decide) (by decide), zero 14 (by decide) (by decide),
    zero 15 (by decide) (by decide)]

theorem accepted_numeric_32 {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {lane : Nat} (lower : 18 ≤ lane) (upper : lane < 46) :
    packedWord packed (42176 + lane) < 4294967296 := by
  have mem : (⟨20 + lane, false, 42176 + lane, 0, 986 + 16 * (lane - 18), 16⟩ : StableEvenRange)
      ∈ stableEvenRanges := by
    apply List.mem_append_right
    apply List.mem_map.mpr
    refine ⟨lane - 18, List.mem_range.mpr (by omega), ?_⟩
    congr 1 <;> omega
  exact (accepted_stable_even_range accepted mem).2

theorem accepted_high_limb_24 {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {slot : Nat} (hs : slot < 6) :
    packedWord packed (42176 + (highLimbSpecs.getD slot (0, 0)).1) < 16777216 := by
  let lane := (highLimbSpecs.getD slot (0, 0)).1
  let start := (highLimbSpecs.getD slot (0, 0)).2
  have mem : (⟨20 + lane, false, 42176 + lane, 0, start, 16⟩ : StableEvenRange)
      ∈ stableEvenRanges := by
    dsimp [lane, start]
    interval_cases slot <;> decide
  have reconstructed := (accepted_stable_even_range accepted mem).1
  change packedWord packed (42176 + lane) =
    radixFourSum (fun d => packedWord packed (42432 + start + d)) 16 at reconstructed
  have zeros : ∀ d, 12 ≤ d → d < 16 →
      packedWord packed (42432 + start + d) = 0 := by
    intro d lower upper
    have raw := accepted_high_digit_zero accepted hs (show d - 12 < 4 by omega)
    change packedWord packed (42432 + start + 12 + (d - 12)) = 0 at raw
    have offset : 42432 + start + 12 + (d - 12) = 42432 + start + d := by omega
    rw [offset] at raw
    exact raw
  rw [radix_four_drop_high zeros] at reconstructed
  change packedWord packed (42176 + lane) < 16777216
  rw [reconstructed]
  apply radix_four_sum_bound
  intro d hd
  have startBound : start < 1330 := by
    dsimp [start]
    interval_cases slot <;> decide
  simpa only [Nat.add_assoc] using
    accepted_stable_range_digit_bound accepted (show start + d < 1472 by omega)

end HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral
