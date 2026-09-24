import HegemonCrypto.SmallWoodV8Smz9StableCollateral
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
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

structure CollateralCoefficients (values publicWords : List Nat) : Prop where
  zero : (values.getD 0 0 : F) = 0
  one : (values.getD 1 0 : F) = 1
  neg : (values.getD 158 0 : F) = -1
  pos : (values.getD 265 0 : F) = 1
  mint : (values.getD 304 0 : F) = 1
  negMint : (values.getD 432 0 : F) = -1
  million : (values.getD 434 0 : F) = 1000000
  radix : (values.getD 448 0 : F) = 4294967296
  negRadix : (values.getD 449 0 : F) = -4294967296
  negMintRadix : (values.getD 480 0 : F) = -4294967296
  negDebt : (values.getD 540 0 : F) = -(publicWords.getD 111 0 : F)
  mintRadix : (values.getD 541 0 : F) = 4294967296
  maximum : (values.getD 542 0 : F) = 4294967295

theorem collateral_coefficients {values publicWords : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (mint : publicWords.getD 83 0 = 1) : CollateralCoefficients values publicWords := by
  have v0 := equations 0 (.constant 0) (by decide)
  have v1 := equations 1 (.constant 1) (by decide)
  have v158 := equations 158 (.sub 0 1) (by decide)
  have v265 := equations 265 (.sub 0 158) (by decide)
  have v87 := equations 87 (.publicWord 83) (by decide)
  have v304 := equations 304 (.selectEqual 87 1 1 0) (by decide)
  have v432 := equations 432 (.mul 158 304) (by decide)
  have v434 := equations 434 (.constant 1000000) (by decide)
  have v448 := equations 448 (.constant 4294967296) (by decide)
  have v449 := equations 449 (.sub 0 448) (by decide)
  have v480 := equations 480 (.mul 304 449) (by decide)
  have v115 := equations 115 (.publicWord 111) (by decide)
  have v539 := equations 539 (.mul 115 304) (by decide)
  have v540 := equations 540 (.sub 0 539) (by decide)
  have v541 := equations 541 (.mul 304 448) (by decide)
  have v542 := equations 542 (.constant 4294967295) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one, Nat.cast_ofNat] at v0 v1 v158 v265 v87 v304 v432 v434 v448 v449 v480 v115 v539 v540 v541 v542
  rw [v0, v1] at v158
  rw [v0, v158] at v265
  rw [v87, mint, Nat.cast_one, v1, if_pos rfl] at v304
  rw [v158, v304] at v432
  rw [v0, v448] at v449
  rw [v304, v449] at v480
  rw [v115, v304] at v539
  rw [v0, v539] at v540
  rw [v304, v448] at v541
  refine ⟨v0, v1, ?_, ?_, ?_, ?_, v434, v448, ?_, ?_, ?_, ?_, v542⟩
  · simpa using v158
  · simpa using v265
  · simpa using v304
  · simpa using v432
  · simpa using v449
  · simpa using v480
  · simpa using v540
  · simpa using v541

structure ProductSpec where
  lane : Nat
  left : Nat
  right : Nat
  low : Nat
  high : Nat
  previous : Nat
deriving DecidableEq, Repr

def productSpecs : List ProductSpec :=
  [⟨5, 42194, 41425, 42196, 42199, 0⟩,
   ⟨6, 42195, 41425, 42197, 42198, 42199⟩,
   ⟨7, 42196, 0, 42200, 42204, 0⟩,
   ⟨8, 42197, 0, 42201, 42205, 42204⟩,
   ⟨9, 42198, 0, 42202, 42203, 42205⟩,
   ⟨10, 42206, 41426, 42208, 42211, 0⟩,
   ⟨11, 42207, 41426, 42209, 42210, 42211⟩,
   ⟨12, 42208, 41421, 42212, 42216, 0⟩,
   ⟨13, 42209, 41421, 42213, 42217, 42216⟩,
   ⟨14, 42210, 41421, 42214, 42215, 42217⟩]

def productAttempt (spec : ProductSpec) (part : Nat) : CsrExecutableAttempt :=
  let i := 3 * (spec.lane - 5) + part
  attempt (20442 + i) 81 i 0
    (if part = 0 then [(42240 + spec.lane, 1), (spec.left, 158)]
    else if part = 1 then [(42304 + spec.lane, 1)] ++
      (if spec.right = 0 then [] else [(spec.right, 158)])
    else [(42368 + spec.lane, 1), (spec.low, 158), (spec.high, 449)] ++
      (if spec.previous = 0 then [] else [(spec.previous, 265)]))
    (if part = 1 ∧ spec.right = 0 then 434 else 0)

def productRight (packed : List Nat) (spec : ProductSpec) : Nat :=
  if spec.right = 0 then 1000000 else packedWord packed spec.right

def productPrevious (packed : List Nat) (spec : ProductSpec) : Nat :=
  if spec.previous = 0 then 0 else packedWord packed spec.previous

theorem exact_product_attempts : ∀ spec, spec ∈ productSpecs → ∀ part, part < 3 →
    productAttempt spec part ∈ exactCsrAttempts := by
  have cert : exactCsrAttempts.filter (fun entry => entry.family == 81) =
      productSpecs.flatMap (fun spec => (List.range 3).map (productAttempt spec)) := by decide
  intro spec hs part hp
  have member : productAttempt spec part ∈ exactCsrAttempts.filter
      (fun entry => entry.family == 81) := by
    rw [cert]
    exact List.mem_flatMap.mpr ⟨spec, hs,
      List.mem_map.mpr ⟨part, List.mem_range.mpr hp, rfl⟩⟩
  exact (List.mem_filter.mp member).1

theorem accepted_collateral_product_field {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0 = 1)
    {spec : ProductSpec} (member : spec ∈ productSpecs) :
    (packedWord packed spec.left : F) * (productRight packed spec : F) +
      (productPrevious packed spec : F) =
      (packedWord packed spec.low : F) + (packedWord packed spec.high : F) * 4294967296 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have c := collateral_coefficients equations mint
  have a := accepted_csr_attempt_field_equality
    (attempts _ (exact_product_attempts spec member 0 (by decide)))
  have b := accepted_csr_attempt_field_equality
    (attempts _ (exact_product_attempts spec member 1 (by decide)))
  have out := accepted_csr_attempt_field_equality
    (attempts _ (exact_product_attempts spec member 2 (by decide)))
  have laneBound : spec.lane < 64 := by
    have cert : productSpecs.all (fun s => decide (s.lane < 64)) = true := by decide
    exact of_decide_eq_true (List.all_eq_true.mp cert spec member)
  have mul := accepted_stable_mul_lane accepted laneBound
  change csrFieldSum values packed [(42240 + spec.lane, 1), (spec.left, 158)] =
    (values.getD 0 0 : F) at a
  change csrFieldSum values packed ([(42304 + spec.lane, 1)] ++
    (if spec.right = 0 then [] else [(spec.right, 158)])) =
    (values.getD (if (1 : Nat) = 1 ∧ spec.right = 0 then 434 else 0) 0 : F) at b
  simp only [true_and] at b
  change csrFieldSum values packed
    ([(42368 + spec.lane, 1), (spec.low, 158), (spec.high, 449)] ++
      (if spec.previous = 0 then [] else [(spec.previous, 265)])) =
    (values.getD 0 0 : F) at out
  have aeq : (packedWord packed (42240 + spec.lane) : F) =
      (packedWord packed spec.left : F) := by
    have raw : (packedWord packed (42240 + spec.lane) : F) +
        -(packedWord packed spec.left : F) = 0 := by
      simpa only [csrFieldSum, List.map_cons, List.map_nil,
        List.sum_cons, List.sum_nil, c.one, c.neg, c.zero,
        one_mul, neg_one_mul, add_zero, packedWord] using a
    exact add_neg_eq_zero.mp raw
  have beq : (packedWord packed (42304 + spec.lane) : F) =
      (productRight packed spec : F) := by
    by_cases constant : spec.right = 0
    · simp only [constant, if_true, List.append_nil] at b
      simpa only [productRight, constant, if_true, Nat.cast_ofNat,
        csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
        List.sum_nil, c.one, c.million, one_mul, add_zero, packedWord] using b
    · have raw : (packedWord packed (42304 + spec.lane) : F) +
          -(packedWord packed spec.right : F) = 0 := by
        simp only [constant, if_false, List.cons_append, List.nil_append] at b
        simpa only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
          List.sum_nil, c.one, c.neg, c.zero, one_mul, neg_one_mul, add_zero, packedWord] using b
      simpa only [productRight, constant, if_false] using add_neg_eq_zero.mp raw
  have ceq : (packedWord packed (42368 + spec.lane) : F) -
      (packedWord packed spec.low : F) -
      (packedWord packed spec.high : F) * 4294967296 +
      (productPrevious packed spec : F) = 0 := by
    by_cases absent : spec.previous = 0
    · simp only [absent, if_true, List.append_nil] at out
      simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
        List.sum_nil, c.one, c.neg, c.negRadix, c.zero, one_mul,
        neg_one_mul, add_zero] at out
      simp only [productPrevious, absent, if_true, Nat.cast_zero, add_zero]
      change (packed.getD (42368 + spec.lane) 0 : F) -
        (packed.getD spec.low 0 : F) -
        (packed.getD spec.high 0 : F) * 4294967296 = 0
      linear_combination out
    · simp only [absent, if_false, List.cons_append, List.nil_append] at out
      simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
        List.sum_nil, c.one, c.neg, c.negRadix, c.pos, c.zero, one_mul,
        neg_one_mul, add_zero] at out
      simp only [productPrevious, absent, if_false]
      change (packed.getD (42368 + spec.lane) 0 : F) -
        (packed.getD spec.low 0 : F) -
        (packed.getD spec.high 0 : F) * 4294967296 +
        (packed.getD spec.previous 0 : F) = 0
      linear_combination out
  rw [aeq, beq] at mul
  linear_combination mul + ceq

def carryLanes : List Nat := [23, 28, 29, 35, 40, 41]

def carryAttempt (slot : Nat) (output : Bool) : CsrExecutableAttempt :=
  let part := if output then 2 else 0
  attempt (20476 + 3 * slot + part) 83 (3 * slot + part) 1
    (if output then [(42386 + slot, 1)]
     else [(42258 + slot, 1), (42176 + carryLanes.getD slot 0, 265)])
    (if output then 304 else 542)

theorem exact_carry_attempts : ∀ slot, slot < 6 → ∀ output,
    carryAttempt slot output ∈ exactCsrAttempts := by
  have cert : exactCsrAttempts.filter
      (fun entry => entry.family == 83 && entry.localIndex % 3 != 1) =
      (List.range 6).flatMap (fun slot => [carryAttempt slot false, carryAttempt slot true]) := by decide
  intro slot hs output
  have member : carryAttempt slot output ∈ exactCsrAttempts.filter
      (fun entry => entry.family == 83 && entry.localIndex % 3 != 1) := by
    rw [cert]
    refine List.mem_flatMap.mpr ⟨slot, List.mem_range.mpr hs, ?_⟩
    cases output <;> simp
  exact (List.mem_filter.mp member).1

theorem accepted_strict_carry {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0 = 1)
    {slot : Nat} (hs : slot < 6) :
    packedWord packed (42176 + carryLanes.getD slot 0) < 4294967295 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have c := collateral_coefficients equations mint
  have a := accepted_csr_attempt_field_equality
    (attempts _ (exact_carry_attempts slot hs false))
  have out := accepted_csr_attempt_field_equality
    (attempts _ (exact_carry_attempts slot hs true))
  simp only [carryAttempt, attempt, Bool.false_eq_true, if_false,
    if_true, csrFieldSum,
    List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
    c.one, c.pos, c.maximum, c.mint, one_mul, add_zero] at a out
  have mul := accepted_stable_mul_lane accepted (lane := 18 + slot) (by omega)
  have ne : packedWord packed (42176 + carryLanes.getD slot 0) ≠ 4294967295 := by
    intro bad
    change packed.getD (42176 + carryLanes.getD slot 0) 0 = 4294967295 at bad
    rw [bad] at a
    have az : (packedWord packed (42258 + slot) : F) = 0 := by
      change (packed.getD (42258 + slot) 0 : F) = 0
      linear_combination a
    change (packedWord packed (42386 + slot) : F) = 1 at out
    have ae : 42240 + (18 + slot) = 42258 + slot := by omega
    have ce : 42368 + (18 + slot) = 42386 + slot := by omega
    rw [ae, ce, az, zero_mul, out] at mul
    exact zero_ne_one mul
  have lower : 18 ≤ carryLanes.getD slot 0 := by interval_cases slot <;> decide
  have upper : carryLanes.getD slot 0 < 46 := by interval_cases slot <;> decide
  have bound := accepted_numeric_32 accepted lower upper
  omega

theorem accepted_collateral_product_nat {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mint : publicWords.getD 83 0 = 1)
    {spec : ProductSpec} (member : spec ∈ productSpecs) :
    packedWord packed spec.left * productRight packed spec +
      productPrevious packed spec =
      packedWord packed spec.low + packedWord packed spec.high * 4294967296 := by
  have numeric : ∀ index, 42194 ≤ index → index < 42222 →
      packedWord packed index < 4294967296 := by
    intro index lower upper
    have raw := accepted_numeric_32 accepted
      (lane := index - 42176) (by omega) (by omega)
    simpa only [show 42176 + (index - 42176) = index by omega] using raw
  have s13 := (accepted_stable_even_range accepted
    (spec := ⟨2, false, 41421, 0, 32, 16⟩) (by decide)).2
  have s17 := (accepted_stable_even_range accepted
    (spec := ⟨3, false, 41425, 0, 48, 16⟩) (by decide)).2
  have s18 := (accepted_stable_even_range accepted
    (spec := ⟨4, false, 41426, 0, 64, 16⟩) (by decide)).2
  change packedWord packed 41421 < 4294967296 at s13
  change packedWord packed 41425 < 4294967296 at s17
  change packedWord packed 41426 < 4294967296 at s18
  have c23 := accepted_strict_carry accepted mint (slot := 0) (by decide)
  have c28 := accepted_strict_carry accepted mint (slot := 1) (by decide)
  have c29 := accepted_strict_carry accepted mint (slot := 2) (by decide)
  have c35 := accepted_strict_carry accepted mint (slot := 3) (by decide)
  have c40 := accepted_strict_carry accepted mint (slot := 4) (by decide)
  have c41 := accepted_strict_carry accepted mint (slot := 5) (by decide)
  have h22 := accepted_high_limb_24 accepted (slot := 1) (by decide)
  have h27 := accepted_high_limb_24 accepted (slot := 2) (by decide)
  have h34 := accepted_high_limb_24 accepted (slot := 4) (by decide)
  have h39 := accepted_high_limb_24 accepted (slot := 5) (by decide)
  norm_num [carryLanes, highLimbSpecs] at c23 c28 c29 c35 c40 c41 h22 h27 h34 h39
  have eq := accepted_collateral_product_field accepted mint member
  apply carry_equation_nat _ _ _ _ _ eq
  all_goals
    simp only [productSpecs, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals
      simp only [productRight, productPrevious]
      norm_num only
      all_goals try simp only [if_true]
      all_goals first | exact numeric _ (by decide) (by decide) | assumption | omega

end HegemonCrypto.SmallWood.V8Smz9SemanticStableCollateral
