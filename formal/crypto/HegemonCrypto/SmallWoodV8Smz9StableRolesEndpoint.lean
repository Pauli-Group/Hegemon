import HegemonCrypto.SmallWoodV8Smz9SemanticStablecoinEnabled
import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableRolesEndpoint

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1024
set_option maxHeartbeats 200000

theorem accepted_role_difference_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (lane : Nat) (laneBound : lane < 64) :
    ∃ limb, limb < 7 ∧ (packed.getD (41536 + 64 * limb + lane) 0 : F) ≠ 0 := by
  by_contra absent
  push Not at absent
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := lane) (root := 8128) laneBound (by decide)
  have nodes : ∀ limb, limb < 7 →
      exactNonlinearExpressions[773 + limb]? = some (.witnessRow (649 + limb)) := by
    intro limb bound
    apply exact_key_nonzero_node
    apply List.mem_append_left
    exact List.mem_map.mpr ⟨limb, List.mem_range.mpr bound, rfl⟩
  have leaves : ∀ limb, limb < 7 → (values.getD (773 + limb) 0 : F) = 0 := by
    intro limb bound
    have equation := equations (773 + limb) (.witnessRow (649 + limb)) (nodes limb bound)
    have rowBound : 649 + limb < Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount := by
      change 649 + limb < 686; omega
    have rowFound :
        (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed lane)[649 + limb]? =
        some (packed.getD ((649 + limb) * 64 + lane) 0) := by
      simp [Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows, rowBound,
        Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor]
    have rowSource :
        (Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessLaneRows packed lane).getD (649 + limb) 0 =
        packed.getD ((649 + limb) * 64 + lane) 0 := by
      simp [List.getD_eq_getElem?_getD, rowFound]
    simp only [expressionField, rowSource] at equation
    have address : (649 + limb) * 64 + lane = 41536 + 64 * limb + lane := by
      omega
    have source : (values.getD (773 + limb) 0 : F) =
        (packed.getD (41536 + 64 * limb + lane) 0 : F) := by
      rw [address] at equation
      exact equation
    exact source.trans (absent limb bound)
  have leaf0 := leaves 0 (by decide)
  have leaf1 := leaves 1 (by decide)
  have leaf2 := leaves 2 (by decide)
  have leaf3 := leaves 3 (by decide)
  have leaf4 := leaves 4 (by decide)
  have leaf5 := leaves 5 (by decide)
  have leaf6 := leaves 6 (by decide)
  have product0 : (values.getD 8028 0 : F) = 0 := by
    simpa only [expressionField, leaf0, zero_mul] using equations 8028 (.mul 773 8027) (exact_key_nonzero_node (by decide))
  have product1 : (values.getD 8045 0 : F) = 0 := by
    simpa only [expressionField, leaf1, zero_mul] using equations 8045 (.mul 774 8044) (exact_key_nonzero_node (by decide))
  have sum1 : (values.getD 8046 0 : F) = 0 := by
    simpa only [expressionField, product0, product1, add_zero] using equations 8046 (.add 8028 8045) (exact_key_nonzero_node (by decide))
  have product2 : (values.getD 8063 0 : F) = 0 := by
    simpa only [expressionField, leaf2, zero_mul] using equations 8063 (.mul 775 8062) (exact_key_nonzero_node (by decide))
  have sum2 : (values.getD 8064 0 : F) = 0 := by
    simpa only [expressionField, sum1, product2, add_zero] using equations 8064 (.add 8046 8063) (exact_key_nonzero_node (by decide))
  have product3 : (values.getD 8080 0 : F) = 0 := by
    simpa only [expressionField, leaf3, zero_mul] using equations 8080 (.mul 776 8079) (exact_key_nonzero_node (by decide))
  have sum3 : (values.getD 8081 0 : F) = 0 := by
    simpa only [expressionField, sum2, product3, add_zero] using equations 8081 (.add 8064 8080) (exact_key_nonzero_node (by decide))
  have product4 : (values.getD 8096 0 : F) = 0 := by
    simpa only [expressionField, leaf4, zero_mul] using equations 8096 (.mul 777 8095) (exact_key_nonzero_node (by decide))
  have sum4 : (values.getD 8097 0 : F) = 0 := by
    simpa only [expressionField, sum3, product4, add_zero] using equations 8097 (.add 8081 8096) (exact_key_nonzero_node (by decide))
  have product5 : (values.getD 8111 0 : F) = 0 := by
    simpa only [expressionField, leaf5, zero_mul] using equations 8111 (.mul 778 8110) (exact_key_nonzero_node (by decide))
  have sum5 : (values.getD 8112 0 : F) = 0 := by
    simpa only [expressionField, sum4, product5, add_zero] using equations 8112 (.add 8097 8111) (exact_key_nonzero_node (by decide))
  have product6 : (values.getD 8125 0 : F) = 0 := by
    simpa only [expressionField, leaf6, zero_mul] using equations 8125 (.mul 779 8124) (exact_key_nonzero_node (by decide))
  have sum6 : (values.getD 8126 0 : F) = 0 := by
    simpa only [expressionField, sum5, product6, add_zero] using equations 8126 (.add 8112 8125) (exact_key_nonzero_node (by decide))
  have scaled : (values.getD 8127 0 : F) = 0 := by
    simpa only [expressionField, sum6, mul_zero] using equations 8127 (.mul 781 8126) (exact_key_nonzero_node (by decide))
  have oneValue : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (exact_key_nonzero_node (by decide))
  have impossible : (0 : F) = -1 := by
    simpa only [expressionField, rootZero, scaled, oneValue, zero_sub] using
      equations 8128 (.sub 8127 1) (exact_key_nonzero_node (by decide))
  exact (neg_ne_zero.mpr (one_ne_zero : (1 : F) ≠ 0)) impossible.symm


def commitmentOffset (role : Nat) : Nat := [6, 24, 31, 38, 48].getD role 0

def commitmentPair (condition : Nat) : Nat × Nat :=
  [(0,1),(0,2),(0,3),(0,4),(1,2),(1,3),(1,4),(2,3),(2,4),(3,4)].getD condition (0,0)

def stableRoleAttempt (condition limb : Nat) : CsrExecutableAttempt :=
  let left := if condition < 5 then condition else (commitmentPair (condition - 5)).1
  attempt (19344 + 7 * condition + limb) 47 (7 * condition + limb) 0
    ([(41536 + 64 * limb + condition, 1), (41408 + commitmentOffset left + limb, 320)] ++
      if condition < 5 then [] else
        [(41408 + commitmentOffset (commitmentPair (condition - 5)).2 + limb, 322)])
    (if limb = 0 then 307 else 0)

set_option maxRecDepth 1000000 in
set_option maxHeartbeats 1000000 in
theorem exact_stable_role_attempts : ∀ condition, condition < 15 → ∀ limb, limb < 7 →
    stableRoleAttempt condition limb ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 47 && entry.localIndex < 105) =
      (List.range 15).flatMap (fun condition => (List.range 7).map (stableRoleAttempt condition)) := by decide
  intro condition conditionBound limb limbBound
  have member : stableRoleAttempt condition limb ∈ exactCsrAttempts.filter
      (fun entry => entry.family == 47 && entry.localIndex < 105) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨condition, List.mem_range.mpr conditionBound,
      List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩⟩
  exact (List.mem_filter.mp member).1

set_option maxRecDepth 1000000 in
set_option maxHeartbeats 1000000 in
theorem accepted_stable_role_sources {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2)
    {condition limb : Nat} (conditionBound : condition < 15) (limbBound : limb < 7) :
    (packed.getD (41536 + 64 * limb + condition) 0 : F) =
      if condition < 5 then (packed.getD (41408 + commitmentOffset condition + limb) 0 : F)
      else (packed.getD (41408 + commitmentOffset (commitmentPair (condition - 5)).1 + limb) 0 : F) -
        (packed.getD (41408 + commitmentOffset (commitmentPair (condition - 5)).2 + limb) 0 : F) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have equations := evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated
  have natEquations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found
  have gate := stable_enabled_gate_value natEquations accepted.1 direction
  have enabled : (values.getD 306 0 : F) = 1 := by
    simp [List.getD_eq_getElem?_getD, gate]
  have zero := equations 0 (.constant 0) (by decide)
  have one := equations 1 (.constant 1) (by decide)
  have negative := equations 158 (.sub 0 1) (by decide)
  have inactive := equations 307 (.sub 1 306) (by decide)
  have n320 := equations 320 (.sub 0 306) (by decide)
  have n321 := equations 321 (.mul 158 306) (by decide)
  have n322 := equations 322 (.sub 0 321) (by decide)
  simp only [expressionField, Nat.cast_zero, Nat.cast_one] at zero one negative inactive n320 n321 n322
  rw [zero, one, zero_sub] at negative
  rw [one, enabled, sub_self] at inactive
  rw [zero, enabled, zero_sub] at n320
  rw [negative, enabled, mul_one] at n321
  rw [zero, n321, zero_sub, neg_neg] at n322
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_stable_role_attempts condition conditionBound limb limbBound))
  have target : (values.getD (stableRoleAttempt condition limb).targetRoot 0 : F) = 0 := by
    by_cases first : limb = 0 <;> simp only [stableRoleAttempt, attempt, first, if_true, if_false,
      inactive, zero]
  rw [target] at equation
  by_cases single : condition < 5
  · simp only [stableRoleAttempt, attempt, single, if_true, List.append_nil, csrFieldSum,
      List.map_cons, List.map_nil, List.sum_cons, List.sum_nil, one, n320,
      one_mul, neg_one_mul, add_zero] at equation
    rw [if_pos single]
    exact add_neg_eq_zero.mp equation
  · simp only [stableRoleAttempt, attempt, single, if_false, List.cons_append, List.nil_append,
      csrFieldSum, List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
      one, n320, n322, one_mul, neg_one_mul, add_zero] at equation
    rw [if_neg single]
    simpa only [neg_add, neg_neg, sub_eq_add_neg] using add_eq_zero_iff_eq_neg.mp equation

/-- The five committed policy roles are nonzero and each of the ten pairs differs in a limb. -/
theorem accepted_stable_commitment_roles {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    (∀ role, role < 5 → ∃ limb, limb < 7 ∧
      packed.getD (41408 + commitmentOffset role + limb) 0 ≠ 0) ∧
    (∀ pair, pair < 10 → ∃ limb, limb < 7 ∧
      packed.getD (41408 + commitmentOffset (commitmentPair pair).1 + limb) 0 ≠
        packed.getD (41408 + commitmentOffset (commitmentPair pair).2 + limb) 0) := by
  constructor
  · intro role roleBound
    obtain ⟨limb, limbBound, nonzero⟩ := accepted_role_difference_nonzero accepted role (by omega)
    have binding := accepted_stable_role_sources accepted direction (by omega : role < 15) limbBound
    rw [if_pos roleBound] at binding
    refine ⟨limb, limbBound, ?_⟩
    intro zero
    rw [zero, Nat.cast_zero] at binding
    exact nonzero binding
  · intro pair pairBound
    obtain ⟨limb, limbBound, nonzero⟩ := accepted_role_difference_nonzero accepted (5 + pair) (by omega)
    have binding := accepted_stable_role_sources accepted direction
      (by omega : 5 + pair < 15) limbBound
    rw [if_neg (by omega), Nat.add_sub_cancel_left] at binding
    refine ⟨limb, limbBound, ?_⟩
    intro equal
    rw [equal, sub_self] at binding
    exact nonzero binding


end HegemonCrypto.SmallWood.V8Smz9SemanticStableRolesEndpoint
