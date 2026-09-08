import HegemonCrypto.SmallWoodV8Smz9StableLifecycleEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint

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
open HegemonCrypto.SmallWood.V8Smz9SemanticStableLifecycleEndpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

def retiredLowPos (i : Nat) : Nat := if i = 0 then 265 else 508+i
def retiredLowNeg (i : Nat) : Nat := 158+i
def retiredHighPos (i : Nat) : Nat := if i = 0 then 265 else if i = 1 then 509 else 523+i
def retiredHighNeg (i : Nat) : Nat := timeHighNegativePower i

def RetirementCoefficientNodes (i : Nat) : Prop :=
  exactCsrExpressions[retiredLowPos i]? = some (.sub 0 (retiredLowNeg i)) ∧
  exactCsrExpressions[retiredHighPos i]? = some (.sub 0 (retiredHighNeg i))

instance (i : Nat) : Decidable (RetirementCoefficientNodes i) := by
  unfold RetirementCoefficientNodes; infer_instance

theorem exact_retirement_coefficient_nodes : ∀ i, i < 16 → RetirementCoefficientNodes i := by
  have checked : (List.range 16).all (fun i => decide (RetirementCoefficientNodes i)) = true := by decide
  simpa only [List.all_eq_true,List.mem_range,decide_eq_true_eq] using checked

theorem retirement_time_coefficients {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (natEquations : CsrTraceEquations publicWords values) :
    (∀ i, i < 16 → (values.getD (retiredLowPos i) 0 : F) = (4 ^ i : Nat)) ∧
    (∀ i, i < 16 → (values.getD (retiredLowNeg i) 0 : F) = -((4 ^ i : Nat) : F)) ∧
    (∀ i, i < 16 → (values.getD (retiredHighPos i) 0 : F) = (4 ^ i : Nat)) ∧
    (∀ i, i < 16 → (values.getD (retiredHighNeg i) 0 : F) = -((4 ^ i : Nat) : F)) ∧
    (values.getD 524 0 : F) = (2 ^ 32 : F) := by
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField,Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have lowNegative (i : Nat) (bound : i < 16) :
      (values.getD (retiredLowNeg i) 0 : F) = -((4 ^ i : Nat) : F) :=
    (dense_negative_coefficient_values natEquations).1 i (by omega)
  have highPower (i : Nat) (bound : i < 16) :
      (values.getD (timeHighPower i) 0 : F) = (4 ^ i : Nat) := by
    simpa only [expressionField] using equations _ _ (exact_time_coefficient_nodes i bound).2.2.2.2.1
  have highNegative (i : Nat) (bound : i < 16) :
      (values.getD (retiredHighNeg i) 0 : F) = -((4 ^ i : Nat) : F) := by
    simpa only [expressionField,zero,highPower i bound,zero_sub,retiredHighNeg] using
      equations _ _ (exact_time_coefficient_nodes i bound).2.2.2.2.2
  refine ⟨?_,lowNegative,?_,highNegative,?_⟩
  · intro i bound
    simpa only [expressionField,zero,lowNegative i bound,zero_sub,neg_neg] using
      equations _ _ (exact_retirement_coefficient_nodes i bound).1
  · intro i bound
    simpa only [expressionField,zero,highNegative i bound,zero_sub,neg_neg] using
      equations _ _ (exact_retirement_coefficient_nodes i bound).2
  · have power : (values.getD 448 0 : F) = 2 ^ 32 := by
      have equation := equations 448 (.constant (2^32)) (by decide)
      norm_num [expressionField] at equation ⊢
      exact equation
    have negative : (values.getD 449 0 : F) = -(2^32:F) := by
      simpa only [expressionField,zero,power,zero_sub] using equations 449 (.sub 0 448) (by decide)
    simpa only [expressionField,zero,negative,zero_sub,neg_neg] using
      equations 524 (.sub 0 449) (by decide)

def retirementGateAttempt (i : Nat) : CsrExecutableAttempt :=
  attempt (20413+2*i) 76 (2*i) 0 [(42265+i,1),(41412,323)] 0

def retirementZeroAttempt (i : Nat) : CsrExecutableAttempt :=
  attempt (20414+2*i) 76 (1+2*i) 0 [(42393+i,1)] 0

theorem exact_retirement_gate_attempts : ∀ i, i < 4 →
    retirementGateAttempt i ∈ exactCsrAttempts ∧ retirementZeroAttempt i ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 76) =
      (List.range 4).flatMap (fun i => [retirementGateAttempt i,retirementZeroAttempt i]) := by decide
  intro i bound
  have both : ∀ entry, entry ∈ [retirementGateAttempt i,retirementZeroAttempt i] → entry ∈ exactCsrAttempts := by
    intro entry member
    have filtered : entry ∈ exactCsrAttempts.filter (fun entry => entry.family == 76) := by
      rw [checked]
      exact List.mem_flatMap.mpr ⟨i,List.mem_range.mpr bound,member⟩
    exact (List.mem_filter.mp filtered).1
  exact ⟨both _ (by simp),both _ (by simp)⟩

theorem accepted_mint_retirement_residual_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) (retired : packedWord packed 41412 = 1)
    (i : Nat) (bound : i < 4) : (packedWord packed (42329+i) : F) = 0 := by
  obtain ⟨values,evaluated,attempts⟩ := accepted.2.2.2
  have equations := evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField,Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField,Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have dir : (values.getD 87 0 : F) = 1 := by
    simpa only [expressionField,direction,Nat.cast_one] using equations 87 (.publicWord 83) (by decide)
  have mint : (values.getD 304 0 : F) = 1 := by
    simpa only [expressionField,dir,one,zero,if_true] using
      equations 304 (.selectEqual 87 1 1 0) (by decide)
  have negative : (values.getD 323 0 : F) = -1 := by
    simpa only [expressionField,zero,mint,zero_sub] using equations 323 (.sub 0 304) (by decide)
  have gateEq := accepted_csr_attempt_field_equality (attempts _ (exact_retirement_gate_attempts i bound).1)
  have zeroEq := accepted_csr_attempt_field_equality (attempts _ (exact_retirement_gate_attempts i bound).2)
  simp only [retirementGateAttempt,retirementZeroAttempt,attempt,csrFieldSum,List.map_cons,List.map_nil,
    List.sum_cons,List.sum_nil,zero,one,negative,one_mul,add_zero] at gateEq zeroEq
  have retiredField : (packed.getD 41412 0 : F) = 1 := by
    simpa only [packedWord,Nat.cast_one] using congrArg (fun n : Nat => (n : F)) retired
  rw [retiredField] at gateEq
  have gate : (packedWord packed (42265+i) : F) = 1 := by
    simp only [packedWord]
    linear_combination gateEq
  have mul := accepted_stable_mul_lane accepted (lane := 25+i) (by omega)
  simp only [show 42240+(25+i) = 42265+i by omega,
    show 42304+(25+i) = 42329+i by omega,
    show 42368+(25+i) = 42393+i by omega] at mul
  rw [gate,one_mul] at mul
  exact mul.trans zeroEq

def retirementAddition (i : Nat) : TimeAdditionSpec :=
  if i = 0 then ⟨0,8,1,27⟩ else ⟨6,9,1,28⟩

def retirementLowAttempt (i : Nat) : CsrExecutableAttempt :=
  let spec := retirementAddition i
  attempt (20421+2*i) 77 (2*i) 0
    ([(42329+2*i,1)] ++ timeDigitTerms (timeSpec spec.x).start 16 retiredLowNeg ++
      timeDigitTerms (timeSpec spec.y).start 16 retiredLowNeg ++
      timeDigitTerms (timeSpec spec.z).start 16 retiredLowPos ++ [(42112+spec.carry,524)]) 1

def retirementHighAttempt (i : Nat) : CsrExecutableAttempt :=
  let spec := retirementAddition i
  attempt (20422+2*i) 77 (1+2*i) 0
    ([(42330+2*i,1)] ++ timeHighTerms (timeSpec spec.x).start (timeSpec spec.x).topLane retiredHighNeg ++
      timeHighTerms (timeSpec spec.y).start (timeSpec spec.y).topLane retiredHighNeg ++
      [(42112+spec.carry,158)] ++
      timeHighTerms (timeSpec spec.z).start (timeSpec spec.z).topLane retiredHighPos) 0

theorem exact_retirement_addition_attempts : ∀ i, i < 2 →
    retirementLowAttempt i ∈ exactCsrAttempts ∧ retirementHighAttempt i ∈ exactCsrAttempts ∧
    (retirementAddition i).x < 14 ∧ (retirementAddition i).y < 14 ∧
      (retirementAddition i).z < 14 ∧ (retirementAddition i).carry < 64 := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 77) =
      (List.range 2).flatMap (fun i => [retirementLowAttempt i,retirementHighAttempt i]) := by decide
  have bounds : ∀ i, i < 2 → (retirementAddition i).x < 14 ∧ (retirementAddition i).y < 14 ∧
      (retirementAddition i).z < 14 ∧ (retirementAddition i).carry < 64 := by
    intro i bound
    interval_cases i <;> decide
  intro i bound
  have both : ∀ entry, entry ∈ [retirementLowAttempt i,retirementHighAttempt i] → entry ∈ exactCsrAttempts := by
    intro entry member
    have filtered : entry ∈ exactCsrAttempts.filter (fun entry => entry.family == 77) := by
      rw [checked]
      exact List.mem_flatMap.mpr ⟨i,List.mem_range.mpr bound,member⟩
    exact (List.mem_filter.mp filtered).1
  exact ⟨both _ (by simp),both _ (by simp),bounds i bound⟩

theorem accepted_mint_retirement_fields {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) (retired : packedWord packed 41412 = 1)
    (i : Nat) (bound : i < 2) :
    let spec := retirementAddition i
    let x := timeSpec spec.x
    let y := timeSpec spec.y
    let z := timeSpec spec.z
    ((timeLow packed x.start + timeLow packed y.start + 1 : Nat) : F) =
      ((timeLow packed z.start + 2^32 * packedWord packed (42112+spec.carry) : Nat) : F) ∧
    ((timeHigh packed x.start x.topLane + timeHigh packed y.start y.topLane +
      packedWord packed (42112+spec.carry) : Nat) : F) = (timeHigh packed z.start z.topLane : F) := by
  obtain ⟨values,evaluated,attempts⟩ := accepted.2.2.2
  have equations := evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated
  have natEquations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField,Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField,Nat.cast_one] using equations 1 (.constant 1) (by decide)
  obtain ⟨lowPositive,lowNegative,highPositive,highNegative,carryCoefficient⟩ :=
    retirement_time_coefficients equations natEquations
  have lowPos (start : Nat) : csrFieldSum values packed (timeDigitTerms start 16 retiredLowPos) =
      (timeLow packed start : F) := by
    simpa only [timeLow,one_mul] using time_digit_field_sum values packed start 16 retiredLowPos 1
      (by intro digit h; simpa only [one_mul] using lowPositive digit h)
  have lowNeg (start : Nat) : csrFieldSum values packed (timeDigitTerms start 16 retiredLowNeg) =
      -(timeLow packed start : F) := by
    simpa only [timeLow,neg_one_mul] using time_digit_field_sum values packed start 16 retiredLowNeg (-1)
      (by intro digit h; simpa only [neg_one_mul] using lowNegative digit h)
  have highPos (start top : Nat) : csrFieldSum values packed (timeHighTerms start top retiredHighPos) =
      (timeHigh packed start top : F) := by
    simpa only [one_mul] using time_high_field_sum values packed start top retiredHighPos 1
      (by intro digit h; simpa only [one_mul] using highPositive digit h)
  have highNeg (start top : Nat) : csrFieldSum values packed (timeHighTerms start top retiredHighNeg) =
      -(timeHigh packed start top : F) := by
    simpa only [neg_one_mul] using time_high_field_sum values packed start top retiredHighNeg (-1)
      (by intro digit h; simpa only [neg_one_mul] using highNegative digit h)
  have negativeOne : (values.getD 158 0 : F) = -1 := by
    simpa only [retiredLowNeg,Nat.add_zero,pow_zero,Nat.cast_one] using lowNegative 0 (by decide)
  have lowResidual := accepted_mint_retirement_residual_zero accepted direction retired (2*i) (by omega)
  have highResidual := accepted_mint_retirement_residual_zero accepted direction retired (1+2*i) (by omega)
  have lowEq := accepted_csr_attempt_field_equality (attempts _ (exact_retirement_addition_attempts i bound).1)
  have highEq := accepted_csr_attempt_field_equality (attempts _ (exact_retirement_addition_attempts i bound).2.1)
  simp only [retirementLowAttempt,retirementHighAttempt,attempt,zero,one] at lowEq highEq
  rw [csr_field_sum_append,csr_field_sum_append,csr_field_sum_append,csr_field_sum_append,
    lowNeg,lowNeg,lowPos] at lowEq
  rw [csr_field_sum_append,csr_field_sum_append,csr_field_sum_append,csr_field_sum_append,
    highNeg,highNeg,highPos] at highEq
  simp only [csrFieldSum,List.map_cons,List.map_nil,List.sum_cons,List.sum_nil,carryCoefficient,
    negativeOne,one,one_mul,add_zero] at lowEq highEq
  simp only [packedWord,show 42329+(1+2*i) = 42330+2*i by omega] at lowResidual highResidual
  rw [lowResidual] at lowEq
  rw [highResidual] at highEq
  dsimp only
  simp only [Nat.cast_add,Nat.cast_mul,Nat.cast_pow,Nat.cast_ofNat,Nat.cast_one,packedWord]
  constructor
  · linear_combination -lowEq
  · linear_combination -highEq

theorem accepted_mint_retirement_addition {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) (retired : packedWord packed 41412 = 1)
    (i : Nat) (bound : i < 2) :
    stableOddSource publicWords packed (timeSpec (retirementAddition i).x) +
      stableOddSource publicWords packed (timeSpec (retirementAddition i).y) + 1 =
        stableOddSource publicWords packed (timeSpec (retirementAddition i).z) := by
  have bounded := (exact_retirement_addition_attempts i bound).2.2
  have x := accepted_time_spec_parts accepted (retirementAddition i).x bounded.1
  have y := accepted_time_spec_parts accepted (retirementAddition i).y bounded.2.1
  have z := accepted_time_spec_parts accepted (retirementAddition i).z bounded.2.2.1
  have carry : packedWord packed (42112+(retirementAddition i).carry) ≤ 1 := by
    rcases accepted_stable_boolean accepted bounded.2.2.2 with h | h <;> omega
  obtain ⟨lowField,highField⟩ := accepted_mint_retirement_fields accepted direction retired i bound
  have low : timeLow packed (timeSpec (retirementAddition i).x).start +
      timeLow packed (timeSpec (retirementAddition i).y).start + 1 =
      timeLow packed (timeSpec (retirementAddition i).z).start +
        2^32 * packedWord packed (42112+(retirementAddition i).carry) := by
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
  have high : timeHigh packed (timeSpec (retirementAddition i).x).start (timeSpec (retirementAddition i).x).topLane +
      timeHigh packed (timeSpec (retirementAddition i).y).start (timeSpec (retirementAddition i).y).topLane +
      packedWord packed (42112+(retirementAddition i).carry) =
        timeHigh packed (timeSpec (retirementAddition i).z).start (timeSpec (retirementAddition i).z).topLane := by
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

theorem accepted_stable_mint_retirement {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) (retired : packedWord packed 41412 = 1) :
    packedWord packed 41411 < packedWord packed 41413 ∧
      publicWords.getD 94 0 < packedWord packed 41413 := by
  have enabled := accepted_mint_retirement_addition accepted direction retired 0 (by decide)
  have parent := accepted_mint_retirement_addition accepted direction retired 1 (by decide)
  change packedWord packed 41411 + packedWord packed 42178 + 1 = packedWord packed 41413 at enabled
  change publicWords.getD 94 0 + packedWord packed 42179 + 1 = packedWord packed 41413 at parent
  omega


end HegemonCrypto.SmallWood.V8Smz9SemanticStableRetirementEndpoint
