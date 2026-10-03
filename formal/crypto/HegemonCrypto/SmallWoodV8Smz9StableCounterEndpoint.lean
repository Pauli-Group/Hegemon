import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabled
import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint

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
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

/-- Every stable multiplication lane is constrained by the actual accepted nonlinear root. -/
theorem accepted_stable_mul_lane {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {lane : Nat} (bound : lane < 64) :
    (packedWord packed (42240 + lane) : F) * (packedWord packed (42304 + lane) : F) =
      (packedWord packed (42368 + lane) : F) := by
  have rootMember : 8132 ∈ exactNonlinearRoots := by decide
  obtain ⟨values, evaluated, rootZero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 lane bound) rootMember
  have equations := evaluated_field_trace_equations
    hgv8rp03_nonlinear_expression_program_is_canonical evaluated
  have left := equations 784 (.witnessRow 660) (by decide)
  have right := equations 785 (.witnessRow 661) (by decide)
  have output := equations 786 (.witnessRow 662) (by decide)
  have mul := equations 8131 (.mul 784 785) (by decide)
  have sub := equations 8132 (.sub 8131 786) (by decide)
  have zero : (values.getD 8132 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, rootZero]
  simp only [expressionField] at left right output mul sub
  rw [zero, mul, left, right, output] at sub
  have row (index : Nat) (rowBound : index < relationRowCount) :
      (packedWitnessLaneRows packed lane).getD index 0 =
        packedWord packed (index * 64 + lane) := by
    simp [packedWitnessLaneRows, packedWord, rowBound, packingFactor]
  rw [row 660 (by decide), row 661 (by decide), row 662 (by decide)] at sub
  exact sub_eq_zero.mp sub.symm

def stableMuxAttempts : List CsrExecutableAttempt :=
  [attempt 20391 74 0 0 [(42255, 1), (42187, 158)] 0,
   attempt 20392 74 1 0 [(42383, 1), (42123, 265)] 1,
   attempt 20393 74 2 0 [(42256, 1), (42123, 158)] 0,
   attempt 20394 74 3 0 [(42320, 1), (41499, 158)] 0,
   attempt 20395 74 4 0 [(42257, 1), (42123, 158)] 0,
   attempt 20396 74 5 0 [(42321, 1), (42187, 158)] 0,
   attempt 20397 74 6 0 [(42385, 1)] 0]

theorem exact_stable_mux_attempts : ∀ entry, entry ∈ stableMuxAttempts →
    entry ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 74) =
      stableMuxAttempts := by decide
  intro entry member
  exact (List.mem_filter.mp (show entry ∈ exactCsrAttempts.filter
    (fun entry => entry.family == 74) by rw [checked]; exact member)).1

/-- The epoch test bit is an actual zero test, and the mint base is its exact Nat mux. -/
theorem accepted_stable_epoch_mux {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    (packedWord packed 42123 = 1 ↔ packedWord packed 42187 = 0) ∧
      packedWord packed 42384 =
        if packedWord packed 42187 = 0 then packedWord packed 41499 else 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have one := equations 1 (.constant 1) (by decide)
  have zero := equations 0 (.constant 0) (by decide)
  have neg := equations 158 (.sub 0 1) (by decide)
  have pos := equations 265 (.sub 0 158) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at one zero neg pos
  rw [zero, one] at neg
  rw [zero, neg] at pos
  simp only [zero_sub, neg_neg] at neg pos
  have eqs : ∀ entry, entry ∈ stableMuxAttempts →
      csrFieldSum values packed entry.terms = (values.getD entry.targetRoot 0 : F) := by
    intro entry member
    exact accepted_csr_attempt_field_equality (attempts _ (exact_stable_mux_attempts entry member))
  have a15 := eqs _ (show attempt 20391 74 0 0 [(42255, 1), (42187, 158)] 0 ∈ stableMuxAttempts by decide)
  have c15 := eqs _ (show attempt 20392 74 1 0 [(42383, 1), (42123, 265)] 1 ∈ stableMuxAttempts by decide)
  have a16 := eqs _ (show attempt 20393 74 2 0 [(42256, 1), (42123, 158)] 0 ∈ stableMuxAttempts by decide)
  have b16 := eqs _ (show attempt 20394 74 3 0 [(42320, 1), (41499, 158)] 0 ∈ stableMuxAttempts by decide)
  have a17 := eqs _ (show attempt 20395 74 4 0 [(42257, 1), (42123, 158)] 0 ∈ stableMuxAttempts by decide)
  have b17 := eqs _ (show attempt 20396 74 5 0 [(42321, 1), (42187, 158)] 0 ∈ stableMuxAttempts by decide)
  have c17 := eqs _ (show attempt 20397 74 6 0 [(42385, 1)] 0 ∈ stableMuxAttempts by decide)
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, one, zero, neg, pos, one_mul, neg_one_mul, add_zero] at a15 c15 a16 b16 a17 b17 c17
  have mul15 := accepted_stable_mul_lane accepted (lane := 15) (by decide)
  have mul16 := accepted_stable_mul_lane accepted (lane := 16) (by decide)
  have mul17 := accepted_stable_mul_lane accepted (lane := 17) (by decide)
  have eq_a15 := add_neg_eq_zero.mp a15
  have eq_a16 := add_neg_eq_zero.mp a16
  have eq_b16 := add_neg_eq_zero.mp b16
  have eq_a17 := add_neg_eq_zero.mp a17
  have eq_b17 := add_neg_eq_zero.mp b17
  simp only [packedWord] at mul15 mul16 mul17 ⊢
  rw [eq_a15] at mul15
  rw [eq_a16, eq_b16] at mul16
  rw [eq_a17, eq_b17, c17] at mul17
  have canonical := packed_word_canonical accepted.2.1
  have test : packed.getD 42123 0 = 1 ↔ packed.getD 42187 0 = 0 := by
    constructor
    · intro bit
      rw [bit, Nat.cast_one, one_mul] at mul17
      exact canonical_nat_cast_injective (canonical _) (by decide) (by simpa using mul17)
    · intro gap
      rw [gap, Nat.cast_zero, zero_mul] at mul15
      have bitField : (packed.getD 42123 0 : F) = 1 := by
        rw [← mul15] at c15
        simpa using c15
      exact canonical_nat_cast_injective (canonical _) (by decide) (by simpa using bitField)
  refine ⟨test, ?_⟩
  by_cases gap : packed.getD 42187 0 = 0
  · rw [if_pos gap]
    rw [test.mpr gap, Nat.cast_one, one_mul] at mul16
    exact canonical_nat_cast_injective (canonical _) (canonical _) mul16.symm
  · have bit : packed.getD 42123 0 = 0 := by
      rcases accepted_stable_boolean accepted (lane := 11) (by decide) with zeroBit | oneBit
      · exact zeroBit
      · exact False.elim (gap (test.mp oneBit))
    rw [if_neg gap]
    rw [bit, Nat.cast_zero, zero_mul] at mul16
    exact canonical_nat_cast_injective (canonical _) (by decide) (by simpa using mul16.symm)

/-- Exact public coefficient DAG for both enabled directions. -/
theorem stable_counter_coefficients {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (isMint : Bool) (direction : publicWords.getD 83 0 = if isMint then 1 else 2) :
    (values.getD 1 0 : F) = 1 ∧ (values.getD 0 0 : F) = 0 ∧
    (values.getD 158 0 : F) = -1 ∧ (values.getD 321 0 : F) = -1 ∧
    (values.getD 422 0 : F) = -((publicWords.getD 94 0 : F) -
      (publicWords.getD 109 0 : F) * 4096) ∧
    (values.getD 425 0 : F) = -((publicWords.getD 110 0 : F) -
      (if isMint then (publicWords.getD 86 0 : F) else 0)) ∧
    (values.getD 429 0 : F) = -((publicWords.getD 111 0 : F) -
      (if isMint then (publicWords.getD 86 0 : F) else -(publicWords.getD 86 0 : F))) := by
  have z := equations 0 (.constant 0) (by decide)
  have o := equations 1 (.constant 1) (by decide)
  have t := equations 2 (.constant 2) (by decide)
  have n := equations 158 (.sub 0 1) (by decide)
  have d := equations 87 (.publicWord 83) (by decide)
  have m := equations 304 (.selectEqual 87 1 1 0) (by decide)
  have b := equations 305 (.selectEqual 87 2 1 0) (by decide)
  have e := equations 306 (.add 304 305) (by decide)
  have ne := equations 321 (.mul 158 306) (by decide)
  have h := equations 98 (.publicWord 94) (by decide)
  have ep := equations 113 (.publicWord 109) (by decide)
  have mag := equations 90 (.publicWord 86) (by decide)
  have minted := equations 114 (.publicWord 110) (by decide)
  have debt := equations 115 (.publicWord 111) (by decide)
  have scale := equations 225 (.constant 4096) (by decide)
  have n419 := equations 419 (.mul 113 225) (by decide)
  have n420 := equations 420 (.sub 98 419) (by decide)
  have n421 := equations 421 (.mul 306 420) (by decide)
  have n422 := equations 422 (.sub 0 421) (by decide)
  have n423 := equations 423 (.mul 90 304) (by decide)
  have n424 := equations 424 (.sub 114 423) (by decide)
  have n425 := equations 425 (.sub 0 424) (by decide)
  have n426 := equations 426 (.sub 304 305) (by decide)
  have n427 := equations 427 (.mul 90 426) (by decide)
  have n428 := equations 428 (.sub 115 427) (by decide)
  have n429 := equations 429 (.sub 0 428) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] at z o t n d m b e ne h ep mag minted debt scale n419 n420 n421 n422 n423 n424 n425 n426 n427 n428 n429
  have two_ne_one : (2 : F) ≠ 1 := by decide
  have mv : (values.getD 304 0 : F) = if isMint then 1 else 0 := by
    rw [m, d, o, z, direction]
    cases isMint <;> norm_num [two_ne_one]
  have bv : (values.getD 305 0 : F) = if isMint then 0 else 1 := by
    rw [b, d, t, o, z, direction]
    cases isMint <;> norm_num [Ne.symm two_ne_one]
  have ev : (values.getD 306 0 : F) = 1 := by
    rw [e, mv, bv]
    cases isMint <;> simp
  have nv : (values.getD 158 0 : F) = -1 := by rw [n, z, o, zero_sub]
  refine ⟨o, z, nv, ?_, ?_, ?_, ?_⟩
  · rw [ne, nv, ev, mul_one]
  · rw [n422, z, n421, ev, one_mul, n420, h, n419, ep, scale, zero_sub]
  · rw [n425, z, n424, minted, n423, mag, mv]
    cases isMint <;> simp
  · rw [n429, z, n428, debt, n427, mag, n426, mv, bv]
    cases isMint <;> simp

theorem accepted_stable_counter_field_equations {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (isMint : Bool) (direction : publicWords.getD 83 0 = if isMint then 1 else 2) :
    (publicWords.getD 94 0 : F) = (publicWords.getD 109 0 : F) * 4096 +
      (packedWord packed 42188 : F) ∧
    (publicWords.getD 110 0 : F) = (packedWord packed 42384 : F) +
      (if isMint then (publicWords.getD 86 0 : F) else 0) ∧
    (publicWords.getD 111 0 : F) = (packedWord packed 41500 : F) +
      (if isMint then (publicWords.getD 86 0 : F) else -(publicWords.getD 86 0 : F)) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  obtain ⟨_, _, neg, negativeEnabled, height, mintTarget, debtTarget⟩ :=
    stable_counter_coefficients equations isMint direction
  have heightEq := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_epoch_cap_attempts (attempt 20325 67 1 1 [(42188, 321)] 422) (by decide)))
  have mintEq := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_epoch_cap_attempts (attempt 20328 67 4 1 [(42384, 158)] 425) (by decide)))
  have debtEq := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_epoch_cap_attempts (attempt 20329 67 5 1 [(41500, 158)] 429) (by decide)))
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, neg, negativeEnabled, height, mintTarget, debtTarget,
    neg_one_mul, add_zero] at heightEq mintEq debtEq
  refine ⟨?_, ?_, ?_⟩
  · have eq := neg_inj.mp heightEq
    simpa only [packedWord, add_comm] using (sub_eq_iff_eq_add.mp eq.symm)
  · have eq := neg_inj.mp mintEq
    simpa only [packedWord] using (sub_eq_iff_eq_add.mp eq.symm)
  · have eq := neg_inj.mp debtEq
    simpa only [packedWord] using (sub_eq_iff_eq_add.mp eq.symm)

/-- Public epoch is floor(parent height / 4096), with an exact bounded remainder. -/
theorem accepted_stable_current_epoch {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (isMint : Bool) (direction : publicWords.getD 83 0 = if isMint then 1 else 2) :
    publicWords.getD 109 0 = publicWords.getD 94 0 / 4096 ∧
      publicWords.getD 94 0 = 4096 * publicWords.getD 109 0 + packedWord packed 42188 := by
  have remainder := (accepted_stable_even_range accepted
    (spec := ⟨36, false, 42188, 0, 966, 6⟩) (by decide)).2
  change packedWord packed 42188 < 4096 at remainder
  have epochBound := (accepted_stable_sequence_epoch_bounds accepted).2.2.2.1
  have sumBound : 4096 * publicWords.getD 109 0 + packedWord packed 42188 < fieldModulus := by
    change publicWords.getD 109 0 < 2251799813685248 at epochBound
    change _ < 18446744069414584321
    omega
  have fieldEq := (accepted_stable_counter_field_equations accepted isMint direction).1
  have natEq : publicWords.getD 94 0 =
      4096 * publicWords.getD 109 0 + packedWord packed 42188 := by
    apply canonical_nat_cast_injective
      (canonical_public_coordinate accepted.1 (index := 94) (by decide)).2 sumBound
    simpa only [Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat, mul_comm] using fieldEq
  refine ⟨?_, natEq⟩
  omega

/-- Exact before/after counter semantics, including same-epoch mint-base and burn subtraction. -/
theorem accepted_stable_counter_transition {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (isMint : Bool) (direction : publicWords.getD 83 0 = if isMint then 1 else 2) :
    let currentEpoch := publicWords.getD 94 0 / 4096
    let mintBase := if packedWord packed 41498 = currentEpoch then packedWord packed 41499 else 0
    packedWord packed 41498 ≤ currentEpoch ∧
    publicWords.getD 109 0 = currentEpoch ∧
    publicWords.getD 110 0 = mintBase + (if isMint then publicWords.getD 86 0 else 0) ∧
    (if isMint then publicWords.getD 111 0 = packedWord packed 41500 + publicWords.getD 86 0
      else publicWords.getD 86 0 ≤ packedWord packed 41500 ∧
        publicWords.getD 111 0 = packedWord packed 41500 - publicWords.getD 86 0) ∧
    publicWords.getD 112 0 = packedWord packed 41501 + 1 := by
  dsimp only
  have epoch := (accepted_stable_current_epoch accepted isMint direction).1
  have gap := (accepted_stable_epoch_gap_and_caps accepted).1
  have gapIff : packedWord packed 42187 = 0 ↔ packedWord packed 41498 = publicWords.getD 94 0 / 4096 := by
    omega
  have mux := (accepted_stable_epoch_mux accepted).2
  have muxEq : packedWord packed 42384 =
      if packedWord packed 41498 = publicWords.getD 94 0 / 4096 then packedWord packed 41499 else 0 := by
    simpa only [gapIff] using mux
  obtain ⟨_, mintEq, debtEq⟩ := accepted_stable_counter_field_equations accepted isMint direction
  obtain ⟨_, _, magBound, beforeMintBound, beforeDebtBound, afterMintBound, afterDebtBound, _, _⟩ :=
    accepted_stable_nine_value_bounds accepted
  have muxBound : packedWord packed 42384 < 2 ^ 56 := by
    rw [mux]
    split <;> omega
  have mintNat : publicWords.getD 110 0 = packedWord packed 42384 +
      (if isMint then publicWords.getD 86 0 else 0) := by
    apply canonical_nat_cast_injective
      (canonical_public_coordinate accepted.1 (index := 110) (by decide)).2
    · change packedWord packed 42384 < 72057594037927936 at muxBound
      change publicWords.getD 86 0 < 72057594037927936 at magBound
      change _ < 18446744069414584321
      cases isMint <;> simp only [Bool.false_eq_true, if_false, if_true] <;> omega
    · cases isMint <;> simpa only [Bool.false_eq_true, if_false, if_true,
        Nat.cast_add, Nat.cast_zero] using mintEq
  have dir : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2 := by
    cases isMint <;> simp_all only [Bool.false_eq_true, if_false, if_true, or_true, true_or]
  refine ⟨by omega, epoch, by rw [mintNat, muxEq], ?_, accepted_stable_enabled_sequence accepted dir⟩
  cases isMint
  · simp only [Bool.false_eq_true, if_false] at debtEq ⊢
    have natDebt : publicWords.getD 111 0 + publicWords.getD 86 0 = packedWord packed 41500 := by
      apply canonical_nat_cast_injective
      · change publicWords.getD 111 0 < 72057594037927936 at afterDebtBound
        change publicWords.getD 86 0 < 72057594037927936 at magBound
        change _ < 18446744069414584321
        omega
      · exact packed_word_canonical accepted.2.1 _
      · simp only [Nat.cast_add]
        rw [debtEq]
        simp
    omega
  · simp only [if_true] at debtEq ⊢
    apply canonical_nat_cast_injective
      (canonical_public_coordinate accepted.1 (index := 111) (by decide)).2
    · change packedWord packed 41500 < 72057594037927936 at beforeDebtBound
      change publicWords.getD 86 0 < 72057594037927936 at magBound
      change _ < 18446744069414584321
      omega
    · simpa only [Nat.cast_add] using debtEq

def stableBasicPolicyAttempts : List CsrExecutableAttempt :=
  [attempt 20331 68 0 1 [(41410, 304)] 433,
   attempt 20332 68 1 1 [(41429, 304)] 0,
   attempt 20333 68 2 1 [(41430, 304)] 433,
   attempt 20334 68 3 1 [(41421, 304), (42184, 432)] 437,
   attempt 20425 78 0 0 [(42264, 1), (41412, 265)] 1,
   attempt 20426 78 1 0 [(42328, 1), (41413, 158)] 0,
   attempt 20427 78 2 0 [(42392, 1)] 0]

theorem exact_stable_basic_policy_attempts : ∀ entry, entry ∈ stableBasicPolicyAttempts →
    entry ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 68 || entry.family == 78) =
      stableBasicPolicyAttempts := by decide
  intro entry member
  exact (List.mem_filter.mp (show entry ∈ exactCsrAttempts.filter
    (fun entry => entry.family == 68 || entry.family == 78) by rw [checked]; exact member)).1

theorem accepted_stable_no_retirement {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (absent : packedWord packed 41412 = 0) : packedWord packed 41413 = 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero := equations 0 (.constant 0) (by decide)
  have one := equations 1 (.constant 1) (by decide)
  have negative := equations 158 (.sub 0 1) (by decide)
  have positive := equations 265 (.sub 0 158) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at zero one negative positive
  rw [zero, one, zero_sub] at negative
  rw [zero, negative, zero_sub, neg_neg] at positive
  have eqs : ∀ entry, entry ∈ stableBasicPolicyAttempts →
      csrFieldSum values packed entry.terms = (values.getD entry.targetRoot 0 : F) := by
    intro entry member
    exact accepted_csr_attempt_field_equality (attempts _ (exact_stable_basic_policy_attempts entry member))
  have a := eqs _ (show attempt 20425 78 0 0 [(42264, 1), (41412, 265)] 1 ∈ stableBasicPolicyAttempts by decide)
  have b := eqs _ (show attempt 20426 78 1 0 [(42328, 1), (41413, 158)] 0 ∈ stableBasicPolicyAttempts by decide)
  have c := eqs _ (show attempt 20427 78 2 0 [(42392, 1)] 0 ∈ stableBasicPolicyAttempts by decide)
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    one, zero, negative, positive, one_mul, neg_one_mul, add_zero] at a b c
  change packed.getD 41412 0 = 0 at absent
  rw [absent, Nat.cast_zero, add_zero] at a
  have eq_b := add_neg_eq_zero.mp b
  have multiplication := accepted_stable_mul_lane accepted (lane := 24) (by decide)
  simp only [packedWord] at multiplication ⊢
  rw [a, eq_b, c, one_mul] at multiplication
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
    (by simpa using multiplication)

/-- Minting requires active policy, undisputed present attestation, and ratio at least one million. -/
theorem accepted_stable_mint_basic_policy {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) :
    packedWord packed 41410 = 1 ∧ packedWord packed 41429 = 0 ∧
      packedWord packed 41430 = 1 ∧ 1000000 ≤ packedWord packed 41421 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero := equations 0 (.constant 0) (by decide)
  have one := equations 1 (.constant 1) (by decide)
  have negative := equations 158 (.sub 0 1) (by decide)
  have publicValue := equations 87 (.publicWord 83) (by decide)
  have mint := equations 304 (.selectEqual 87 1 1 0) (by decide)
  have n432 := equations 432 (.mul 158 304) (by decide)
  have n433 := equations 433 (.sub 0 432) (by decide)
  have scale := equations 434 (.constant 1000000) (by decide)
  have n435 := equations 435 (.sub 0 434) (by decide)
  have n436 := equations 436 (.mul 304 435) (by decide)
  have n437 := equations 437 (.sub 0 436) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] at zero one negative publicValue mint n432 n433 scale n435 n436 n437
  rw [zero, one, zero_sub] at negative
  rw [publicValue, direction, Nat.cast_one, one, zero, if_pos rfl] at mint
  rw [negative, mint, mul_one] at n432
  rw [zero, n432, zero_sub, neg_neg] at n433
  rw [zero, scale, zero_sub] at n435
  rw [mint, n435, one_mul] at n436
  rw [zero, n436, zero_sub, neg_neg] at n437
  have eqs : ∀ entry, entry ∈ stableBasicPolicyAttempts →
      csrFieldSum values packed entry.terms = (values.getD entry.targetRoot 0 : F) := by
    intro entry member
    exact accepted_csr_attempt_field_equality (attempts _ (exact_stable_basic_policy_attempts entry member))
  have active := eqs _ (show attempt 20331 68 0 1 [(41410, 304)] 433 ∈ stableBasicPolicyAttempts by decide)
  have disputed := eqs _ (show attempt 20332 68 1 1 [(41429, 304)] 0 ∈ stableBasicPolicyAttempts by decide)
  have present := eqs _ (show attempt 20333 68 2 1 [(41430, 304)] 433 ∈ stableBasicPolicyAttempts by decide)
  have ratio := eqs _ (show attempt 20334 68 3 1 [(41421, 304), (42184, 432)] 437 ∈ stableBasicPolicyAttempts by decide)
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    mint, zero, n432, n433, n437, one_mul, neg_one_mul, add_zero] at active disputed present ratio
  have canonical := packed_word_canonical accepted.2.1
  refine ⟨canonical_nat_cast_injective (canonical _) (by decide) (by simpa only [packedWord, Nat.cast_one] using active),
    canonical_nat_cast_injective (canonical _) (by decide) (by simpa only [packedWord, Nat.cast_zero] using disputed),
    canonical_nat_cast_injective (canonical _) (by decide) (by simpa only [packedWord, Nat.cast_one] using present), ?_⟩
  have slackBound := (accepted_stable_even_range accepted
    (spec := ⟨6, false, 42184, 0, 96, 16⟩) (by decide)).2
  change packedWord packed 42184 < 4294967296 at slackBound
  have ratioNat : packedWord packed 41421 = 1000000 + packedWord packed 42184 := by
    apply canonical_nat_cast_injective (canonical _)
    · change _ < 18446744069414584321
      omega
    · simp only [Nat.cast_add, Nat.cast_ofNat]
      exact sub_eq_iff_eq_add.mp (by simpa only [sub_eq_add_neg, packedWord] using ratio)
  omega


end HegemonCrypto.SmallWood.V8Smz9SemanticStableCounterEndpoint
