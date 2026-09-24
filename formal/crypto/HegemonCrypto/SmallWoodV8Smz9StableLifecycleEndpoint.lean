import HegemonCrypto.SmallWoodV8Smz9StableCounterEndpoint
import Mathlib.Tactic.Ring
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint

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

theorem radix_four_sum_succ (digits : Nat → Nat) (n : Nat) :
    radixFourSum digits (n+1) = radixFourSum digits n + 4 ^ n * digits n := by
  simp [radixFourSum, List.range_succ]

theorem radix_four_sum_split (digits : Nat → Nat) (left right : Nat) :
    radixFourSum digits (left+right) = radixFourSum digits left +
      4 ^ left * radixFourSum (fun i => digits (left+i)) right := by
  induction right with
  | zero => simp [radixFourSum]
  | succ n ih =>
    rw [show left + (n+1) = (left+n)+1 by omega, radix_four_sum_succ, ih, radix_four_sum_succ]
    simp only [pow_add, Nat.mul_add, Nat.mul_assoc, Nat.add_assoc]

def timeLow (packed : List Nat) (start : Nat) : Nat :=
  radixFourSum (fun digit => packedWord packed (42432+start+digit)) 16

def timeHigh (packed : List Nat) (start topLane : Nat) : Nat :=
  radixFourSum (fun digit => packedWord packed (42432+start+16+digit)) 15 +
    4 ^ 15 * packedWord packed (42112+topLane)

theorem accepted_stable_time_parts {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (spec : StableOddRange) (member : spec ∈ stableOddRanges) (width : spec.digits = 31) :
    stableOddSource publicWords packed spec = timeLow packed spec.start +
      2 ^ 32 * timeHigh packed spec.start spec.topLane ∧
    timeLow packed spec.start < 2 ^ 32 ∧ timeHigh packed spec.start spec.topLane < 2 ^ 31 := by
  have valid := exact_stable_odd_ranges.1 spec member
  have source := (accepted_stable_odd_range accepted member).1
  have digitBound (i : Nat) (bound : i < 31) : packedWord packed (42432+spec.start+i) < 4 := by
    have length := valid.2.1
    rw [width] at length
    simpa only [Nat.add_assoc] using accepted_stable_range_digit_bound accepted
      (digit := spec.start+i) (by omega)
  have lowBound : timeLow packed spec.start < 4 ^ 16 := by
    exact radix_four_sum_bound _ 16 (by intro i h; exact digitBound i (by omega))
  have highLowBound : radixFourSum
      (fun digit => packedWord packed (42432+spec.start+16+digit)) 15 < 4 ^ 15 := by
    apply radix_four_sum_bound
    intro i h
    simpa only [Nat.add_assoc] using digitBound (16+i) (by omega)
  have topBound : packedWord packed (42112+spec.topLane) ≤ 1 := by
    rcases accepted_stable_boolean accepted valid.2.2.1 with h | h <;> omega
  have highBound : timeHigh packed spec.start spec.topLane < 2 ^ 31 := by
    have product := Nat.mul_le_mul_left (4 ^ 15) topBound
    simp only [timeHigh]
    norm_num only [Nat.reducePow] at highLowBound product ⊢
    omega
  refine ⟨?_, lowBound, highBound⟩
  rw [source]
  simp only [stableOddNatural, width, timeLow, timeHigh]
  have split := radix_four_sum_split (fun digit => packedWord packed (42432+spec.start+digit)) 16 15
  rw [show (31 : Nat) = 16+15 by decide, split]
  simp only [Nat.add_assoc]
  norm_num only [Nat.reducePow]
  ring

def timeSpecs : List StableOddRange :=
  [⟨7,false,41411,0,112,31,33⟩, ⟨8,false,41413,0,143,31,34⟩,
   ⟨9,false,41423,0,174,31,35⟩, ⟨10,false,41424,0,205,31,36⟩,
   ⟨11,false,41428,0,236,31,37⟩, ⟨12,false,41431,0,267,31,38⟩,
   ⟨14,true,94,405,329,31,40⟩, ⟨17,false,42177,0,422,31,43⟩,
   ⟨18,false,42178,0,453,31,44⟩, ⟨19,false,42179,0,484,31,45⟩,
   ⟨20,false,42180,0,515,31,46⟩, ⟨21,false,42181,0,546,31,47⟩,
   ⟨22,false,42182,0,577,31,48⟩, ⟨23,false,42183,0,608,31,49⟩]

def timeSpec (i : Nat) : StableOddRange := timeSpecs.getD i ⟨7,false,41411,0,112,31,33⟩

theorem exact_time_specs : ∀ i, i < 14 → timeSpec i ∈ stableOddRanges ∧ (timeSpec i).digits = 31 := by
  have checked : (List.range 14).all (fun i => decide
      (timeSpec i ∈ stableOddRanges ∧ (timeSpec i).digits = 31)) = true := by decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

theorem accepted_time_spec_parts {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (i : Nat) (bound : i < 14) :
    stableOddSource publicWords packed (timeSpec i) = timeLow packed (timeSpec i).start +
      2 ^ 32 * timeHigh packed (timeSpec i).start (timeSpec i).topLane ∧
    timeLow packed (timeSpec i).start < 2 ^ 32 ∧
      timeHigh packed (timeSpec i).start (timeSpec i).topLane < 2 ^ 31 :=
  accepted_stable_time_parts accepted _ (exact_time_specs i bound).1 (exact_time_specs i bound).2

def timeLowPos (i : Nat) : Nat := if i = 0 then 304 else 449+i
def timeLowNeg (i : Nat) : Nat := if i = 0 then 432 else 464+i
def timeHighPos (i : Nat) : Nat := if i = 0 then 304 else if i = 1 then 450 else 479+i
def timeHighNeg (i : Nat) : Nat := if i = 0 then 432 else if i = 1 then 465 else 493+i
def timeHighPower (i : Nat) : Nat := if i = 0 then 1 else if i = 1 then 128 else 201+4*i
def timeHighNegativePower (i : Nat) : Nat := if i = 0 then 158 else if i = 1 then 159 else 202+4*i

def TimeCoefficientNodes (i : Nat) : Prop :=
  (i ≠ 0 → exactCsrExpressions[timeLowPos i]? = some (.mul (densePowerRoot i) 304)) ∧
  exactCsrExpressions[timeLowNeg i]? = some (.mul (158+i) 304) ∧
  (i ≠ 0 → exactCsrExpressions[timeHighPos i]? = some (.mul (timeHighPower i) 304)) ∧
  exactCsrExpressions[timeHighNeg i]? = some (.mul (timeHighNegativePower i) 304) ∧
  exactCsrExpressions[timeHighPower i]? = some (.constant (4 ^ i)) ∧
  exactCsrExpressions[timeHighNegativePower i]? = some (.sub 0 (timeHighPower i))

instance (i : Nat) : Decidable (TimeCoefficientNodes i) := by unfold TimeCoefficientNodes; infer_instance

theorem exact_time_coefficient_nodes : ∀ i, i < 16 → TimeCoefficientNodes i := by
  have checked : (List.range 16).all (fun i => decide (TimeCoefficientNodes i)) = true := by decide
  simpa only [List.all_eq_true, List.mem_range, decide_eq_true_eq] using checked

theorem mint_time_coefficients {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (natEquations : CsrTraceEquations publicWords values)
    (mint : (values.getD 304 0 : F) = 1) :
    (∀ i, i < 16 → (values.getD (timeLowPos i) 0 : F) = (4 ^ i : Nat)) ∧
    (∀ i, i < 16 → (values.getD (timeLowNeg i) 0 : F) = -((4 ^ i : Nat) : F)) ∧
    (∀ i, i < 16 → (values.getD (timeHighPos i) 0 : F) = (4 ^ i : Nat)) ∧
    (∀ i, i < 16 → (values.getD (timeHighNeg i) 0 : F) = -((4 ^ i : Nat) : F)) ∧
    (values.getD 480 0 : F) = -(2 ^ 32 : F) := by
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have powers (i : Nat) (bound : i < 16) :
      (values.getD (timeHighPower i) 0 : F) = (4 ^ i : Nat) := by
    simpa only [expressionField] using equations _ _ (exact_time_coefficient_nodes i bound).2.2.2.2.1
  have negatives (i : Nat) (bound : i < 16) :
      (values.getD (timeHighNegativePower i) 0 : F) = -((4 ^ i : Nat) : F) := by
    simpa only [expressionField, zero, powers i bound, zero_sub] using
      equations _ _ (exact_time_coefficient_nodes i bound).2.2.2.2.2
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · intro i bound
    by_cases isZero : i = 0
    · subst i
      simpa only [timeLowPos, if_true, pow_zero, Nat.cast_one] using mint
    · have power := dense_power_values natEquations i (by omega)
      have powerValue : (values.getD (densePowerRoot i) 0 : F) = (4 ^ i : Nat) := by
        simp only [List.getD_eq_getElem?_getD, power, Option.getD_some]
      simpa only [expressionField, powerValue, mint, mul_one] using
        equations _ _ ((exact_time_coefficient_nodes i bound).1 isZero)
  · intro i bound
    have power := (dense_negative_coefficient_values natEquations).1 i (by omega)
    simpa only [expressionField, power, mint, mul_one] using
      equations _ _ (exact_time_coefficient_nodes i bound).2.1
  · intro i bound
    by_cases isZero : i = 0
    · subst i
      simpa only [timeHighPos, if_true, pow_zero, Nat.cast_one] using mint
    · simpa only [expressionField, powers i bound, mint, mul_one] using
        equations _ _ ((exact_time_coefficient_nodes i bound).2.2.1 isZero)
  · intro i bound
    simpa only [expressionField, negatives i bound, mint, mul_one] using
      equations _ _ (exact_time_coefficient_nodes i bound).2.2.2.1
  · have power : (values.getD 448 0 : F) = 2 ^ 32 := by
      have equation := equations 448 (.constant (2^32)) (by decide)
      norm_num [expressionField] at equation ⊢
      exact equation
    have negative : (values.getD 449 0 : F) = -(2^32:F) := by
      simpa only [expressionField, zero, power, zero_sub] using equations 449 (.sub 0 448) (by decide)
    simpa only [expressionField, mint, negative, one_mul] using equations 480 (.mul 304 449) (by decide)

def timeDigitTerms (start count : Nat) (coefficient : Nat → Nat) : List (Nat × Nat) :=
  (List.range count).map (fun i => (42432+start+i, coefficient i))

theorem csr_field_sum_append (values packed : List Nat) (left right : List (Nat × Nat)) :
    csrFieldSum values packed (left++right) = csrFieldSum values packed left + csrFieldSum values packed right := by
  simp only [csrFieldSum, List.map_append, List.sum_append]

theorem time_digit_field_sum (values packed : List Nat) (start count : Nat)
    (coefficient : Nat → Nat) (sign : F)
    (coefficients : ∀ i, i < count → (values.getD (coefficient i) 0 : F) = sign * ((4^i:Nat):F)) :
    csrFieldSum values packed (timeDigitTerms start count coefficient) =
      sign * (radixFourSum (fun i => packedWord packed (42432+start+i)) count : F) := by
  induction count with
  | zero => simp [timeDigitTerms, csrFieldSum, radixFourSum]
  | succ n ih =>
    have prior := ih (by intro i bound; exact coefficients i (by omega))
    have expand : csrFieldSum values packed (timeDigitTerms start (n+1) coefficient) =
        csrFieldSum values packed (timeDigitTerms start n coefficient) +
          (values.getD (coefficient n) 0 : F) * (packedWord packed (42432+start+n) : F) := by
      simp [timeDigitTerms, csrFieldSum, List.range_succ, packedWord]
    rw [expand, prior, coefficients n (by omega), radix_four_sum_succ]
    simp only [Nat.cast_add, Nat.cast_mul]
    ring

def timeHighTerms (start top : Nat) (coefficient : Nat → Nat) : List (Nat × Nat) :=
  timeDigitTerms (start+16) 15 coefficient ++ [(42112+top, coefficient 15)]

theorem time_high_field_sum (values packed : List Nat) (start top : Nat)
    (coefficient : Nat → Nat) (sign : F)
    (coefficients : ∀ i, i < 16 → (values.getD (coefficient i) 0 : F) = sign * ((4^i:Nat):F)) :
    csrFieldSum values packed (timeHighTerms start top coefficient) =
      sign * (timeHigh packed start top : F) := by
  unfold timeHighTerms
  rw [csr_field_sum_append, time_digit_field_sum values packed (start+16) 15 coefficient sign
    (by intro i bound; exact coefficients i (by omega))]
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    coefficients 15 (by decide), add_zero, timeHigh, Nat.cast_add, Nat.cast_mul, packedWord, Nat.add_assoc]
  ring

structure TimeAdditionSpec where
  x : Nat
  y : Nat
  z : Nat
  carry : Nat
deriving DecidableEq

def timeAdditions : List TimeAdditionSpec :=
  [⟨0,7,6,26⟩,⟨2,10,6,29⟩,⟨10,11,3,30⟩,⟨4,12,6,31⟩,⟨12,13,5,32⟩]

def timeAddition (i : Nat) : TimeAdditionSpec := timeAdditions.getD i ⟨0,7,6,26⟩

def timeAdditionLowAttempt (i : Nat) : CsrExecutableAttempt :=
  let spec := timeAddition i
  attempt (20398+3*i) 75 (3*i) 1
    (timeDigitTerms (timeSpec spec.x).start 16 timeLowPos ++
     timeDigitTerms (timeSpec spec.y).start 16 timeLowPos ++
     timeDigitTerms (timeSpec spec.z).start 16 timeLowNeg ++ [(42112+spec.carry,480)]) 0

def timeAdditionHighAttempt (i : Nat) : CsrExecutableAttempt :=
  let spec := timeAddition i
  attempt (20399+3*i) 75 (1+3*i) 1
    (timeHighTerms (timeSpec spec.x).start (timeSpec spec.x).topLane timeHighPos ++
     timeHighTerms (timeSpec spec.y).start (timeSpec spec.y).topLane timeHighPos ++
     [(42112+spec.carry,304)] ++
     timeHighTerms (timeSpec spec.z).start (timeSpec spec.z).topLane timeHighNeg) 0

theorem exact_time_addition_attempts : ∀ i, i < 5 →
    timeAdditionLowAttempt i ∈ exactCsrAttempts ∧ timeAdditionHighAttempt i ∈ exactCsrAttempts ∧
      (timeAddition i).x < 14 ∧ (timeAddition i).y < 14 ∧ (timeAddition i).z < 14 ∧ (timeAddition i).carry < 64 := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 75 && entry.localIndex % 3 < 2) =
      (List.range 5).flatMap (fun i => [timeAdditionLowAttempt i,timeAdditionHighAttempt i]) := by decide
  have bounds : ∀ i, i < 5 → (timeAddition i).x < 14 ∧ (timeAddition i).y < 14 ∧
      (timeAddition i).z < 14 ∧ (timeAddition i).carry < 64 := by
    intro i bound
    interval_cases i <;> decide
  intro i bound
  have both : ∀ entry, entry ∈ [timeAdditionLowAttempt i,timeAdditionHighAttempt i] → entry ∈ exactCsrAttempts := by
    intro entry member
    have filtered : entry ∈ exactCsrAttempts.filter (fun entry => entry.family == 75 && entry.localIndex % 3 < 2) := by
      rw [checked]
      exact List.mem_flatMap.mpr ⟨i,List.mem_range.mpr bound,member⟩
    exact (List.mem_filter.mp filtered).1
  exact ⟨both _ (by simp),both _ (by simp),bounds i bound⟩

theorem accepted_mint_time_fields {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) (i : Nat) (bound : i < 5) :
    let spec := timeAddition i
    let x := timeSpec spec.x
    let y := timeSpec spec.y
    let z := timeSpec spec.z
    ((timeLow packed x.start + timeLow packed y.start : Nat) : F) =
      ((timeLow packed z.start + 2^32 * packedWord packed (42112+spec.carry) : Nat) : F) ∧
    ((timeHigh packed x.start x.topLane + timeHigh packed y.start y.topLane +
      packedWord packed (42112+spec.carry) : Nat) : F) = (timeHigh packed z.start z.topLane : F) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have equations := evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated
  have natEquations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have dir : (values.getD 87 0 : F) = 1 := by
    simpa only [expressionField, direction, Nat.cast_one] using equations 87 (.publicWord 83) (by decide)
  have mint : (values.getD 304 0 : F) = 1 := by
    simpa only [expressionField, dir, one, zero, if_true] using
      equations 304 (.selectEqual 87 1 1 0) (by decide)
  obtain ⟨lowPositive,lowNegative,highPositive,highNegative,carryCoefficient⟩ :=
    mint_time_coefficients equations natEquations mint
  have lowPos (start : Nat) : csrFieldSum values packed (timeDigitTerms start 16 timeLowPos) =
      (timeLow packed start : F) := by
    simpa only [timeLow, one_mul] using time_digit_field_sum values packed start 16 timeLowPos 1
      (by intro digit h; simpa only [one_mul] using lowPositive digit h)
  have lowNeg (start : Nat) : csrFieldSum values packed (timeDigitTerms start 16 timeLowNeg) =
      -(timeLow packed start : F) := by
    simpa only [timeLow, neg_one_mul] using time_digit_field_sum values packed start 16 timeLowNeg (-1)
      (by intro digit h; simpa only [neg_one_mul] using lowNegative digit h)
  have highPos (start top : Nat) : csrFieldSum values packed (timeHighTerms start top timeHighPos) =
      (timeHigh packed start top : F) := by
    simpa only [one_mul] using time_high_field_sum values packed start top timeHighPos 1
      (by intro digit h; simpa only [one_mul] using highPositive digit h)
  have highNeg (start top : Nat) : csrFieldSum values packed (timeHighTerms start top timeHighNeg) =
      -(timeHigh packed start top : F) := by
    simpa only [neg_one_mul] using time_high_field_sum values packed start top timeHighNeg (-1)
      (by intro digit h; simpa only [neg_one_mul] using highNegative digit h)
  have lowEq := accepted_csr_attempt_field_equality
    (attempts _ (exact_time_addition_attempts i bound).1)
  have highEq := accepted_csr_attempt_field_equality
    (attempts _ (exact_time_addition_attempts i bound).2.1)
  simp only [timeAdditionLowAttempt, timeAdditionHighAttempt, attempt, zero] at lowEq highEq
  rw [csr_field_sum_append,csr_field_sum_append,csr_field_sum_append,lowPos,lowPos,lowNeg] at lowEq
  rw [csr_field_sum_append,csr_field_sum_append,csr_field_sum_append,highPos,highPos,highNeg] at highEq
  simp only [csrFieldSum,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,carryCoefficient,mint,
    one_mul,add_zero] at lowEq highEq
  dsimp only
  simp only [Nat.cast_add,Nat.cast_mul,Nat.cast_pow,Nat.cast_ofNat,packedWord]
  constructor
  · linear_combination lowEq
  · linear_combination highEq

/-- Actual low32/high31 equations exclude modular wrap in every mint freshness relation. -/
theorem accepted_mint_time_addition {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) (i : Nat) (bound : i < 5) :
    stableOddSource publicWords packed (timeSpec (timeAddition i).x) +
      stableOddSource publicWords packed (timeSpec (timeAddition i).y) =
        stableOddSource publicWords packed (timeSpec (timeAddition i).z) := by
  have bounded := (exact_time_addition_attempts i bound).2.2
  have x := accepted_time_spec_parts accepted (timeAddition i).x bounded.1
  have y := accepted_time_spec_parts accepted (timeAddition i).y bounded.2.1
  have z := accepted_time_spec_parts accepted (timeAddition i).z bounded.2.2.1
  have carry : packedWord packed (42112+(timeAddition i).carry) ≤ 1 := by
    rcases accepted_stable_boolean accepted bounded.2.2.2 with h | h <;> omega
  obtain ⟨lowField,highField⟩ := accepted_mint_time_fields accepted direction i bound
  have low : timeLow packed (timeSpec (timeAddition i).x).start +
      timeLow packed (timeSpec (timeAddition i).y).start =
      timeLow packed (timeSpec (timeAddition i).z).start +
        2^32 * packedWord packed (42112+(timeAddition i).carry) := by
    apply canonical_nat_cast_injective
    · have xb := x.2.1
      have yb := y.2.1
      norm_num only [Nat.reducePow] at xb yb
      change _ < 18446744069414584321
      omega
    · have zb := z.2.1
      norm_num only [Nat.reducePow] at zb ⊢
      change _ < 18446744069414584321
      omega
    · exact lowField
  have high : timeHigh packed (timeSpec (timeAddition i).x).start (timeSpec (timeAddition i).x).topLane +
      timeHigh packed (timeSpec (timeAddition i).y).start (timeSpec (timeAddition i).y).topLane +
      packedWord packed (42112+(timeAddition i).carry) =
        timeHigh packed (timeSpec (timeAddition i).z).start (timeSpec (timeAddition i).z).topLane := by
    apply canonical_nat_cast_injective
    · have xb := x.2.2
      have yb := y.2.2
      norm_num only [Nat.reducePow] at xb yb
      change _ < 18446744069414584321
      omega
    · have zb := z.2.2
      norm_num only [Nat.reducePow] at zb
      change _ < 18446744069414584321
      omega
    · exact highField
  rw [x.1,y.1,z.1]
  norm_num only [Nat.reducePow] at low ⊢
  omega

theorem accepted_stable_mint_freshness {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) :
    packedWord packed 41411 ≤ publicWords.getD 94 0 ∧
    packedWord packed 41423 ≤ publicWords.getD 94 0 ∧
    publicWords.getD 94 0 - packedWord packed 41423 ≤ packedWord packed 41424 ∧
    packedWord packed 41428 ≤ publicWords.getD 94 0 ∧
    publicWords.getD 94 0 - packedWord packed 41428 ≤ packedWord packed 41431 := by
  have a0 := accepted_mint_time_addition accepted direction 0 (by decide)
  have a1 := accepted_mint_time_addition accepted direction 1 (by decide)
  have a2 := accepted_mint_time_addition accepted direction 2 (by decide)
  have a3 := accepted_mint_time_addition accepted direction 3 (by decide)
  have a4 := accepted_mint_time_addition accepted direction 4 (by decide)
  change packedWord packed 41411 + packedWord packed 42177 = publicWords.getD 94 0 at a0
  change packedWord packed 41423 + packedWord packed 42180 = publicWords.getD 94 0 at a1
  change packedWord packed 42180 + packedWord packed 42181 = packedWord packed 41424 at a2
  change packedWord packed 41428 + packedWord packed 42182 = publicWords.getD 94 0 at a3
  change packedWord packed 42182 + packedWord packed 42183 = packedWord packed 41431 at a4
  omega


end HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
