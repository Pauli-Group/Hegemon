import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoin

/-!
Core source-derived enabled-stablecoin arithmetic. The imported stablecoin extension
and this module require a coordinator-authorized strict check before integration.
The unrestricted enabled transition is not asserted by these range lemmas.
-/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashInitialIndex)
open Hegemon.Transaction.Poseidon2V8RelationProgram
    (CsrExecutableAttempt FieldExpression evalFieldExpression fieldNormalize
     fieldSub fieldMul packingFactor)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

/-- The actual stable Boolean row, including every explicit range top bit. -/
theorem accepted_stable_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {lane : Nat} (bound : lane < 64) :
    packedWord packed (42112 + lane) = 0 ∨ packedWord packed (42112 + lane) = 1 := by
  have member : BooleanWitnessRoot.mk 658 8129 8130 ∈ exactBooleanWitnessRoots := by decide
  simpa only [packedWord, packingFactor] using
    accepted_packed_boolean_witness_rows accepted member bound

structure StableOddRange where
  localIndex : Nat
  isPublic : Bool
  sourceIndex : Nat
  targetRoot : Nat
  start : Nat
  digits : Nat
  topLane : Nat
deriving DecidableEq, Repr

/-- All 17 scalar/sequence ranges and all three 51-bit epoch ranges. -/
def stableOddRanges : List StableOddRange :=
  [⟨7, false, 41411, 0, 112, 31, 33⟩,
   ⟨8, false, 41413, 0, 143, 31, 34⟩,
   ⟨9, false, 41423, 0, 174, 31, 35⟩,
   ⟨10, false, 41424, 0, 205, 31, 36⟩,
   ⟨11, false, 41428, 0, 236, 31, 37⟩,
   ⟨12, false, 41431, 0, 267, 31, 38⟩,
   ⟨13, false, 41455, 0, 298, 31, 39⟩,
   ⟨14, true, 94, 405, 329, 31, 40⟩,
   ⟨15, false, 41501, 0, 360, 31, 41⟩,
   ⟨16, true, 112, 406, 391, 31, 42⟩,
   ⟨17, false, 42177, 0, 422, 31, 43⟩,
   ⟨18, false, 42178, 0, 453, 31, 44⟩,
   ⟨19, false, 42179, 0, 484, 31, 45⟩,
   ⟨20, false, 42180, 0, 515, 31, 46⟩,
   ⟨21, false, 42181, 0, 546, 31, 47⟩,
   ⟨22, false, 42182, 0, 577, 31, 48⟩,
   ⟨23, false, 42183, 0, 608, 31, 49⟩,
   ⟨24, false, 41498, 0, 639, 25, 50⟩,
   ⟨25, true, 109, 409, 664, 25, 51⟩,
   ⟨26, false, 42187, 0, 689, 25, 52⟩]

def stableOddCoefficient (digit : Nat) : Nat := if digit < 30 then 158 + digit else 402
def stableOddTopRoot (spec : StableOddRange) : Nat := if spec.digits = 31 then 403 else 407
def stableOddTopNegativeRoot (spec : StableOddRange) : Nat :=
  if spec.digits = 31 then 404 else 408

def stableOddNegativeTerms (spec : StableOddRange) : List (Nat × Nat) :=
  (List.range spec.digits).map (fun digit =>
    (42432 + spec.start + digit, stableOddCoefficient digit)) ++
    [(42112 + spec.topLane, stableOddTopNegativeRoot spec)]

def stableOddAttempt (spec : StableOddRange) : CsrExecutableAttempt :=
  attempt (20192 + spec.localIndex) 60 spec.localIndex 0
    ((if spec.isPublic then [] else [(spec.sourceIndex, 1)]) ++ stableOddNegativeTerms spec)
    spec.targetRoot

def StableOddRange.Valid (spec : StableOddRange) : Prop :=
  (spec.digits = 25 ∨ spec.digits = 31) ∧
    spec.start + spec.digits ≤ 1472 ∧ spec.topLane < 64 ∧
    spec.sourceIndex < (if spec.isPublic then 120 else 43904) ∧
    2 * 4 ^ spec.digits < Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus ∧
    exactCsrExpressions[stableOddTopRoot spec]? = some (.constant (4 ^ spec.digits)) ∧
    exactCsrExpressions[stableOddTopNegativeRoot spec]? =
      some (.sub 0 (stableOddTopRoot spec)) ∧
    if spec.isPublic then
      exactCsrExpressions[spec.targetRoot]? = some (.sub 0 (4 + spec.sourceIndex)) ∧
      exactCsrExpressions[4 + spec.sourceIndex]? = some (.publicWord spec.sourceIndex)
    else spec.targetRoot = 0

instance (spec : StableOddRange) : Decidable spec.Valid := by
  unfold StableOddRange.Valid
  infer_instance

theorem exact_stable_odd_ranges :
    (∀ spec, spec ∈ stableOddRanges → spec.Valid) ∧
      (∀ spec, spec ∈ stableOddRanges → stableOddAttempt spec ∈ exactCsrAttempts) := by
  have checked : stableOddRanges.all (fun spec => decide spec.Valid) = true := by decide
  have attempts : exactCsrAttempts.filter (fun entry => entry.family == 60 &&
      7 ≤ entry.localIndex && entry.localIndex < 27) =
      stableOddRanges.map stableOddAttempt := by decide
  constructor
  · simpa only [List.all_eq_true, decide_eq_true_eq] using checked
  · intro spec member
    have filtered : stableOddAttempt spec ∈ exactCsrAttempts.filter
        (fun entry => entry.family == 60 && 7 ≤ entry.localIndex && entry.localIndex < 27) := by
      rw [attempts]
      exact List.mem_map.mpr ⟨spec, member, rfl⟩
    exact (List.mem_filter.mp filtered).1

def stableOddSource (publicWords packed : List Nat) (spec : StableOddRange) : Nat :=
  if spec.isPublic then publicWords.getD spec.sourceIndex 0 else packedWord packed spec.sourceIndex

def stableOddNatural (packed : List Nat) (spec : StableOddRange) : Nat :=
  radixFourSum (fun digit => packedWord packed (42432 + spec.start + digit)) spec.digits +
    4 ^ spec.digits * packedWord packed (42112 + spec.topLane)

theorem stable_odd_coefficient_values {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values) {digit : Nat} (bound : digit < 31) :
    (values.getD (stableOddCoefficient digit) 0 : F) = -((4 ^ digit : Nat) : F) := by
  by_cases small : digit < 30
  · simpa only [stableOddCoefficient, if_pos small] using
      (dense_negative_coefficient_values equations).1 digit small
  · have digitEq : digit = 30 := by omega
    subst digit
    have constants := csr_trace_zero_one_values equations
    have fourValue : values[128]? = some 4 := by
      simpa [densePowerRoot] using dense_power_values equations 1 (by decide)
    have prior : values[156]? = some (4 ^ 29) := by
      simpa [densePowerRoot] using dense_power_values equations 29 (by decide)
    have powerValue : values[157]? = some (4 ^ 30) := by
      simpa [evalFieldExpression, densePowerRoot, fourValue, prior, fieldMul,
        fieldNormalize, Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
        equations 157 (.mul 128 156) (by decide)
    have negative : values[402]? = some (fieldSub 0 (4 ^ 30)) := by
      simpa [evalFieldExpression, constants.1, powerValue] using
        equations 402 (.sub 0 157) (by decide)
    simp only [stableOddCoefficient, Nat.lt_irrefl, if_false,
      List.getD_eq_getElem?_getD, negative, Option.getD_some]
    rw [field_sub_cast 0 (4 ^ 30) (by decide)]
    simp

theorem stable_odd_top_coefficient {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (spec : StableOddRange) (valid : spec.Valid) :
    (values.getD (stableOddTopNegativeRoot spec) 0 : F) = -((4 ^ spec.digits : Nat) : F) := by
  have constants := csr_trace_zero_one_values equations
  have powerBound : 4 ^ spec.digits <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    have := valid.2.2.2.2.1
    omega
  have powerValue : values[stableOddTopRoot spec]? = some (4 ^ spec.digits) := by
    simpa only [evalFieldExpression, fieldNormalize, Nat.mod_eq_of_lt powerBound] using
      equations _ _ valid.2.2.2.2.2.1
  have negative : values[stableOddTopNegativeRoot spec]? =
      some (fieldSub 0 (4 ^ spec.digits)) := by
    simpa [evalFieldExpression, constants.1, powerValue] using
      equations _ _ valid.2.2.2.2.2.2.1
  simp only [List.getD_eq_getElem?_getD, negative, Option.getD_some]
  rw [field_sub_cast 0 (4 ^ spec.digits) (by omega)]
  simp

theorem stable_odd_negative_field_sum {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values) (packed : List Nat)
    (spec : StableOddRange) (valid : spec.Valid) :
    csrFieldSum values packed (stableOddNegativeTerms spec) = -(stableOddNatural packed spec : F) := by
  have digitMap :
      (List.range spec.digits).map (fun digit =>
        (values.getD (stableOddCoefficient digit) 0 : F) *
          (packedWord packed (42432 + spec.start + digit) : F)) =
      ((List.range spec.digits).map (fun digit =>
        4 ^ digit * packedWord packed (42432 + spec.start + digit))).map
          (fun (term : Nat) => -(term : F)) := by
    rw [List.map_map]
    apply List.map_congr_left
    intro digit member
    have bound : digit < 31 := by
      have := List.mem_range.mp member
      rcases valid.1 with width | width <;> omega
    rw [stable_odd_coefficient_values equations bound]
    simp only [Function.comp_apply, Nat.cast_mul, neg_mul]
  unfold csrFieldSum stableOddNegativeTerms
  rw [List.map_append, List.sum_append, List.map_map,
    List.map_singleton, List.sum_singleton]
  change ((List.range spec.digits).map (fun digit =>
    (values.getD (stableOddCoefficient digit) 0 : F) *
      (packedWord packed (42432 + spec.start + digit) : F))).sum +
    (values.getD (stableOddTopNegativeRoot spec) 0 : F) *
      (packedWord packed (42112 + spec.topLane) : F) = _
  rw [digitMap, sum_neg_cast, stable_odd_top_coefficient equations spec valid]
  change -(radixFourSum (fun digit => packedWord packed (42432 + spec.start + digit)) spec.digits : F) +
    -((4 ^ spec.digits : Nat) : F) * (packedWord packed (42112 + spec.topLane) : F) = _
  simp only [stableOddNatural, Nat.cast_add, Nat.cast_mul, neg_mul, neg_add]

/-- Exact integer reconstruction; the top bit is proved, not supplied. -/
theorem accepted_stable_odd_range {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {spec : StableOddRange} (member : spec ∈ stableOddRanges) :
    stableOddSource publicWords packed spec = stableOddNatural packed spec ∧
      stableOddSource publicWords packed spec < 2 * 4 ^ spec.digits := by
  have valid := exact_stable_odd_ranges.1 spec member
  have lowBound : radixFourSum
      (fun digit => packedWord packed (42432 + spec.start + digit)) spec.digits < 4 ^ spec.digits := by
    apply radix_four_sum_bound
    intro digit bound
    have raw := accepted_stable_range_digit_bound accepted
      (show spec.start + digit < 1472 by have := valid.2.1; omega)
    simpa only [Nat.add_assoc] using raw
  have topBound : packedWord packed (42112 + spec.topLane) ≤ 1 := by
    rcases accepted_stable_boolean accepted valid.2.2.1 with zero | one <;> omega
  have topTerm := Nat.mul_le_mul_left (4 ^ spec.digits) topBound
  have naturalBound : stableOddNatural packed spec < 2 * 4 ^ spec.digits := by
    unfold stableOddNatural
    omega
  have sourceBound : stableOddSource publicWords packed spec <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    cases publicCase : spec.isPublic with
    | false => simpa [stableOddSource, publicCase,
        Hegemon.Transaction.Poseidon2V8SemanticSpecification.fieldModulus,
        Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
        packed_word_canonical accepted.2.1 spec.sourceIndex
    | true =>
      have indexBound : spec.sourceIndex < 120 := by simpa [publicCase] using valid.2.2.2.1
      simpa [stableOddSource, publicCase] using (canonical_public_coordinate accepted.1 indexBound).2
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have negative := stable_odd_negative_field_sum equations packed spec valid
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_stable_odd_ranges.2 spec member))
  have fieldEqual : (stableOddSource publicWords packed spec : F) =
      (stableOddNatural packed spec : F) := by
    cases publicCase : spec.isPublic with
    | false =>
      have targetZero : spec.targetRoot = 0 := by
        simpa only [publicCase, Bool.false_eq_true, if_false] using valid.2.2.2.2.2.2.2
      simp only [stableOddAttempt, attempt, publicCase, Bool.false_eq_true, if_false,
        List.cons_append, List.nil_append] at equation
      rw [csr_field_sum_cons, oneValue, one_mul, negative, targetZero, zeroValue] at equation
      simpa only [stableOddSource, publicCase, Bool.false_eq_true, if_false, packedWord] using
        add_neg_eq_zero.mp equation
    | true =>
      have nodes : exactCsrExpressions[spec.targetRoot]? = some (.sub 0 (4 + spec.sourceIndex)) ∧
          exactCsrExpressions[4 + spec.sourceIndex]? = some (.publicWord spec.sourceIndex) := by
        simpa only [publicCase, if_true] using valid.2.2.2.2.2.2.2
      have publicBound : spec.sourceIndex < 120 := by
        simpa only [publicCase, if_true] using valid.2.2.2.1
      have coordinate := canonical_public_coordinate accepted.1 publicBound
      have publicValue : values[4 + spec.sourceIndex]? = some (publicWords.getD spec.sourceIndex 0) := by
        simpa only [evalFieldExpression, coordinate.1, Option.map_some, fieldNormalize,
          Nat.mod_eq_of_lt coordinate.2] using equations _ _ nodes.2
      have targetValue : values[spec.targetRoot]? = some (fieldSub 0 (publicWords.getD spec.sourceIndex 0)) := by
        simpa [evalFieldExpression, constants.1, publicValue] using equations _ _ nodes.1
      have targetField : (values.getD spec.targetRoot 0 : F) =
          -(publicWords.getD spec.sourceIndex 0 : F) := by
        have targetGetD : values.getD spec.targetRoot 0 =
            fieldSub 0 (publicWords.getD spec.sourceIndex 0) := by
          simp only [List.getD_eq_getElem?_getD, targetValue, Option.getD_some]
        rw [targetGetD, field_sub_cast 0 _ (by have := coordinate.2; omega)]
        simp
      simp only [stableOddAttempt, attempt, publicCase, if_true, List.nil_append] at equation
      rw [negative, targetField] at equation
      simpa only [stableOddSource, publicCase, if_true] using (neg_inj.mp equation).symm
  have exactNat := canonical_nat_cast_injective sourceBound
    (naturalBound.trans valid.2.2.2.2.1) fieldEqual
  exact ⟨exactNat, by rw [exactNat]; exact naturalBound⟩

theorem accepted_stable_sequence_epoch_bounds {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedWord packed 41501 < 2 ^ 63 ∧ publicWords.getD 112 0 < 2 ^ 63 ∧
      packedWord packed 41498 < 2 ^ 51 ∧ publicWords.getD 109 0 < 2 ^ 51 ∧
      packedWord packed 42187 < 2 ^ 51 := by
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · exact (accepted_stable_odd_range accepted
      (spec := ⟨15, false, 41501, 0, 360, 31, 41⟩) (by decide)).2
  · exact (accepted_stable_odd_range accepted
      (spec := ⟨16, true, 112, 406, 391, 31, 42⟩) (by decide)).2
  · exact (accepted_stable_odd_range accepted
      (spec := ⟨24, false, 41498, 0, 639, 25, 50⟩) (by decide)).2
  · exact (accepted_stable_odd_range accepted
      (spec := ⟨25, true, 109, 409, 664, 25, 51⟩) (by decide)).2
  · exact (accepted_stable_odd_range accepted
      (spec := ⟨26, false, 42187, 0, 689, 25, 52⟩) (by decide)).2

def stableEpochCapAttempts : List CsrExecutableAttempt :=
  [attempt 20324 67 0 1 [(41498, 1), (42187, 1)] 418,
   attempt 20325 67 1 1 [(42188, 321)] 422,
   attempt 20326 67 2 1 [(41499, 1), (42185, 1), (41422, 158)] 0,
   attempt 20327 67 3 1 [(42186, 1), (41422, 158)] 411,
   attempt 20328 67 4 1 [(42384, 158)] 425,
   attempt 20329 67 5 1 [(41500, 158)] 429,
   attempt 20330 67 6 1 [(41501, 158)] 431]

theorem exact_stable_epoch_cap_attempts : ∀ entry, entry ∈ stableEpochCapAttempts →
    entry ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter
      (fun entry => entry.family == 67) = stableEpochCapAttempts := by decide
  intro entry member
  have filtered : entry ∈ exactCsrAttempts.filter
      (fun entry => entry.family == 67) := by
    rw [checked]
    exact member
  exact (List.mem_filter.mp filtered).1

theorem stable_csr_public_value {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    {index : Nat} (bound : index < 120)
    (node : exactCsrExpressions[4 + index]? = some (.publicWord index)) :
    values[4 + index]? = some (publicWords.getD index 0) := by
  have coordinate := canonical_public_coordinate canonical bound
  simpa only [evalFieldExpression, coordinate.1, Option.map_some, fieldNormalize,
    Nat.mod_eq_of_lt coordinate.2] using equations _ _ node

theorem stable_csr_public_negative {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    {index root : Nat} (bound : index < 120)
    (publicNode : exactCsrExpressions[4 + index]? = some (.publicWord index))
    (negativeNode : exactCsrExpressions[root]? = some (.sub 0 (4 + index))) :
    values[root]? = some (fieldSub 0 (publicWords.getD index 0)) ∧
      (values.getD root 0 : F) = -(publicWords.getD index 0 : F) := by
  have constants := csr_trace_zero_one_values equations
  have publicValue := stable_csr_public_value equations canonical bound publicNode
  have negative : values[root]? = some (fieldSub 0 (publicWords.getD index 0)) := by
    simpa [evalFieldExpression, constants.1, publicValue] using equations _ _ negativeNode
  refine ⟨negative, ?_⟩
  have negativeGetD : values.getD root 0 = fieldSub 0 (publicWords.getD index 0) := by
    simp only [List.getD_eq_getElem?_getD, negative, Option.getD_some]
  rw [negativeGetD,
    field_sub_cast 0 _ (by have := (canonical_public_coordinate canonical bound).2; omega)]
  simp

/-- Exact Nat epoch-gap and both cap equations, without a direction premise. -/
theorem accepted_stable_epoch_gap_and_caps {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedWord packed 41498 + packedWord packed 42187 = publicWords.getD 109 0 ∧
      packedWord packed 41499 + packedWord packed 42185 = packedWord packed 41422 ∧
      publicWords.getD 110 0 + packedWord packed 42186 = packedWord packed 41422 := by
  obtain ⟨_, _, beforeEpochBound, _, epochGapBound⟩ := accepted_stable_sequence_epoch_bounds accepted
  obtain ⟨capBound, _, _, beforeBound, _, afterBound, _, slack9Bound, slack10Bound⟩ :=
    accepted_stable_nine_value_bounds accepted
  norm_num at beforeEpochBound epochGapBound capBound beforeBound afterBound slack9Bound slack10Bound
  have afterBoundGetD : publicWords.getD 110 0 < 72057594037927936 := by
    rw [List.getD_eq_getElem?_getD]
    exact afterBound
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa using (dense_negative_coefficient_values equations).1 0 (by decide)
  have negativeEpoch := stable_csr_public_negative equations accepted.1
    (index := 109) (root := 409) (by decide) (by decide) (by decide)
  have negativeAfter := stable_csr_public_negative equations accepted.1
    (index := 110) (root := 411) (by decide) (by decide) (by decide)
  have epochTarget : values[418]? = some (fieldSub 0 (fieldSub 0 (publicWords.getD 109 0))) := by
    simpa [evalFieldExpression, constants.1, negativeEpoch.1] using
      equations 418 (.sub 0 409) (by decide)
  have epochTargetField : (values.getD 418 0 : F) = (publicWords.getD 109 0 : F) := by
    have epochTargetGetD : values.getD 418 0 =
        fieldSub 0 (fieldSub 0 (publicWords.getD 109 0)) := by
      simp only [List.getD_eq_getElem?_getD, epochTarget, Option.getD_some]
    rw [epochTargetGetD]
    rw [field_sub_cast 0 _ (by
      have : fieldSub 0 (publicWords.getD 109 0) <
          Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus :=
        Nat.mod_lt _ (by decide)
      omega)]
    rw [field_sub_cast 0 _ (by
      have := (canonical_public_coordinate accepted.1 (index := 109) (by decide)).2
      omega)]
    simp
  have epochEquation := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_epoch_cap_attempts
      (attempt 20324 67 0 1 [(41498, 1), (42187, 1)] 418) (by decide)))
  have beforeEquation := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_epoch_cap_attempts
      (attempt 20326 67 2 1 [(41499, 1), (42185, 1), (41422, 158)] 0) (by decide)))
  have afterEquation := accepted_csr_attempt_field_equality (attempts _
    (exact_stable_epoch_cap_attempts
      (attempt 20327 67 3 1 [(42186, 1), (41422, 158)] 411) (by decide)))
  simp only [attempt, csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    oneValue, zeroValue, negative, one_mul, neg_one_mul, add_zero,
    epochTargetField, negativeAfter.2] at epochEquation beforeEquation afterEquation
  have epochField : ((packedWord packed 41498 + packedWord packed 42187 : Nat) : F) =
      (publicWords.getD 109 0 : F) := by
    simpa only [Nat.cast_add, packedWord] using epochEquation
  have beforeField : ((packedWord packed 41499 + packedWord packed 42185 : Nat) : F) =
      (packedWord packed 41422 : F) := by
    apply add_neg_eq_zero.mp
    simpa only [Nat.cast_add, packedWord, add_assoc] using beforeEquation
  have afterField : ((publicWords.getD 110 0 + packedWord packed 42186 : Nat) : F) =
      (packedWord packed 41422 : F) := by
    simp only [Nat.cast_add, packedWord]
    have subEquation : (packed.getD 42186 0 : F) - (packed.getD 41422 0 : F) =
        -(publicWords.getD 110 0 : F) := by
      simpa only [sub_eq_add_neg] using afterEquation
    have sourceEquation : (packed.getD 42186 0 : F) =
        -(publicWords.getD 110 0 : F) + (packed.getD 41422 0 : F) :=
      sub_eq_iff_eq_add.mp subEquation
    calc
      (publicWords.getD 110 0 : F) + (packed.getD 42186 0 : F) =
          (publicWords.getD 110 0 : F) +
            (-(publicWords.getD 110 0 : F) + (packed.getD 41422 0 : F)) :=
        congrArg (fun value : F => (publicWords.getD 110 0 : F) + value) sourceEquation
      _ = (packed.getD 41422 0 : F) := add_neg_cancel_left _ _
  refine ⟨?_, ?_, ?_⟩
  · exact canonical_nat_cast_injective
      (by change _ < 18446744069414584321; omega)
      (canonical_public_coordinate accepted.1 (index := 109) (by decide)).2 epochField
  · exact canonical_nat_cast_injective
      (by change _ < 18446744069414584321; omega)
      (packed_word_canonical accepted.2.1 _) beforeField
  · exact canonical_nat_cast_injective
      (by change _ < 18446744069414584321; omega)
      (packed_word_canonical accepted.2.1 _) afterField

theorem accepted_stable_epoch_and_cap_inequalities {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    packedWord packed 41498 ≤ publicWords.getD 109 0 ∧
      packedWord packed 41499 ≤ packedWord packed 41422 ∧
      publicWords.getD 110 0 ≤ packedWord packed 41422 := by
  obtain ⟨epoch, before, after⟩ := accepted_stable_epoch_gap_and_caps accepted
  omega

theorem stable_enabled_gate_value {publicWords values : List Nat}
    (equations : CsrTraceEquations publicWords values)
    (canonical : Hegemon.Transaction.Poseidon2V8RelationProgram.CanonicalPublicWords publicWords)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    values[306]? = some 1 := by
  have constants := csr_trace_zero_one_values equations
  have publicValue := stable_csr_public_value equations canonical (index := 83) (by decide) (by decide)
  have twoValue : values[2]? = some 2 := by
    simpa [evalFieldExpression, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 2 (.constant 2) (by decide)
  have mintEquation := equations 304 (.selectEqual 87 1 1 0) (by decide)
  have burnEquation := equations 305 (.selectEqual 87 2 1 0) (by decide)
  have enabledEquation := equations 306 (.add 304 305) (by decide)
  rcases direction with mint | burn
  · rw [mint] at publicValue
    have mintValue : values[304]? = some 1 := by
      simpa [evalFieldExpression, publicValue, constants.1, constants.2] using mintEquation
    have burnValue : values[305]? = some 0 := by
      simpa [evalFieldExpression, publicValue, constants.1, constants.2, twoValue] using burnEquation
    simpa [evalFieldExpression, mintValue, burnValue,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using enabledEquation
  · rw [burn] at publicValue
    have mintValue : values[304]? = some 0 := by
      simpa [evalFieldExpression, publicValue, constants.1, constants.2] using mintEquation
    have burnValue : values[305]? = some 1 := by
      simpa [evalFieldExpression, publicValue, constants.1, constants.2, twoValue] using burnEquation
    simpa [evalFieldExpression, mintValue, burnValue,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldAdd, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using enabledEquation

def stableConfigFlagSource (slot : Nat) : Nat :=
  [41410, 41412, 41429, 41430].getD slot 0

def stableConfigFlagAttempt (slot : Nat) : CsrExecutableAttempt :=
  attempt (19325 + slot) 44 slot 0
    [(42115 + slot, 1), (stableConfigFlagSource slot, 3)] 0

theorem exact_stable_config_flag_attempts : ∀ slot, slot < 4 →
    stableConfigFlagAttempt slot ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 44) =
      (List.range 4).map stableConfigFlagAttempt := by decide
  intro slot bound
  have filtered : stableConfigFlagAttempt slot ∈ exactCsrAttempts.filter
      (fun entry => entry.family == 44) := by
    rw [checked]
    exact List.mem_map.mpr ⟨slot, List.mem_range.mpr bound, rfl⟩
  exact (List.mem_filter.mp filtered).1

/-- Active, retired-present, disputed, and attestation-present source flags. -/
theorem accepted_stable_config_flag_boolean {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {slot : Nat} (bound : slot < 4) :
    packedWord packed (stableConfigFlagSource slot) = 0 ∨
      packedWord packed (stableConfigFlagSource slot) = 1 := by
  obtain ⟨values, equations, attempts⟩ := accepted_trace_equations accepted
  have constants := csr_trace_zero_one_values equations
  have minusFound : values[3]? = some (fieldSub 0 1) := by
    simpa [evalFieldExpression, fieldSub, fieldNormalize,
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus] using
      equations 3 (.constant 18446744069414584320) (by decide)
  have minusValue : (values.getD 3 0 : F) = -1 := by
    simp only [List.getD_eq_getElem?_getD, minusFound, Option.getD_some]
    rw [field_sub_cast 0 1 (by decide)]
    simp
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, constants.2]
  have zeroValue : (values.getD 0 0 : F) = 0 := by
    simp [List.getD_eq_getElem?_getD, constants.1]
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_stable_config_flag_attempts slot bound))
  simp only [stableConfigFlagAttempt, attempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, oneValue, minusValue, zeroValue,
    one_mul, neg_one_mul, add_zero] at equation
  have copied : packedWord packed (42115 + slot) =
      packedWord packed (stableConfigFlagSource slot) :=
    canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
      (packed_word_canonical accepted.2.1 _) (add_neg_eq_zero.mp equation)
  have bool := accepted_stable_boolean accepted (lane := 3 + slot) (by omega)
  have address : 42112 + (3 + slot) = 42115 + slot := by omega
  simpa only [address, copied] using bool


end HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
