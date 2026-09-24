import HegemonCrypto.SmallWoodV8Smz9StableRequiredNonzeroEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStablePublicNonzeroEndpoint

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRolesEndpoint
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

def publicRequiredProduct (i : Nat) : Nat := if i = 0 then 324 else if i = 1 then 326 else 326+i
def publicRequiredCoefficient (i : Nat) : Nat := if i = 0 then 325 else 326+i

def PublicRequiredNodes (i : Nat) : Prop :=
  exactCsrExpressions[90+i]? = some (.publicWord (86+i)) ∧
  exactCsrExpressions[publicRequiredProduct i]? = some (.mul (90+i) 306) ∧
  (i < 2 → exactCsrExpressions[publicRequiredCoefficient i]? = some (.add 307 (publicRequiredProduct i))) ∧
  (2 ≤ i → publicRequiredCoefficient i = publicRequiredProduct i)

instance (i : Nat) : Decidable (PublicRequiredNodes i) := by unfold PublicRequiredNodes; infer_instance

theorem exact_public_required_nodes : ∀ i, i < 8 → PublicRequiredNodes i := by
  have checked : (List.range 8).all (fun i => decide (PublicRequiredNodes i)) = true := by decide
  simpa only [List.all_eq_true,List.mem_range,decide_eq_true_eq] using checked

theorem enabled_public_required_coefficients {publicWords values : List Nat}
    (equations : FieldTraceEquations publicWords [] values exactCsrExpressions)
    (enabled : (values.getD 306 0 : F) = 1) :
    ∀ i, i < 8 → (values.getD (publicRequiredCoefficient i) 0 : F) = (publicWords.getD (86+i) 0 : F) := by
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField,Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField,Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have inactive : (values.getD 307 0 : F) = 0 := by
    simpa only [expressionField,one,enabled,sub_self] using equations 307 (.sub 1 306) (by decide)
  intro i bound
  have publicValue : (values.getD (90+i) 0 : F) = (publicWords.getD (86+i) 0 : F) := by
    simpa only [expressionField] using equations _ _ (exact_public_required_nodes i bound).1
  have product : (values.getD (publicRequiredProduct i) 0 : F) = (publicWords.getD (86+i) 0 : F) := by
    simpa only [expressionField,publicValue,enabled,mul_one] using equations _ _ (exact_public_required_nodes i bound).2.1
  by_cases early : i < 2
  · simpa only [expressionField,inactive,product,zero_add] using
      equations _ _ ((exact_public_required_nodes i bound).2.2.1 early)
  · rw [(exact_public_required_nodes i bound).2.2.2 (by omega)]
    exact product

def publicRequiredRole (kind : Nat) : Nat := if kind = 0 then 16 else 20

def publicRequiredAttempt (kind limb : Nat) : CsrExecutableAttempt :=
  let role := publicRequiredRole kind
  attempt (19344+7*role+limb) 47 (7*role+limb) 0 [(41536+64*limb+role,1)]
    (if kind = 0 then (if limb = 0 then publicRequiredCoefficient 0 else 0)
      else publicRequiredCoefficient (1+limb))

theorem exact_public_required_attempts : ∀ kind, kind < 2 → ∀ limb, limb < 7 →
    publicRequiredAttempt kind limb ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 47 &&
      (entry.localIndex / 7 == 16 || entry.localIndex / 7 == 20)) =
      (List.range 2).flatMap (fun kind => (List.range 7).map (publicRequiredAttempt kind)) := by decide
  intro kind bound limb limbBound
  have filtered : publicRequiredAttempt kind limb ∈ exactCsrAttempts.filter (fun entry => entry.family == 47 &&
      (entry.localIndex / 7 == 16 || entry.localIndex / 7 == 20)) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨kind,List.mem_range.mpr bound,
      List.mem_map.mpr ⟨limb,List.mem_range.mpr limbBound,rfl⟩⟩
  exact (List.mem_filter.mp filtered).1

theorem accepted_public_required_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2)
    (kind : Nat) (bound : kind < 2) (limb : Nat) (limbBound : limb < 7) :
    (packed.getD (41536+64*limb+publicRequiredRole kind) 0 : F) =
      if kind = 0 then (if limb = 0 then (publicWords.getD 86 0 : F) else 0)
      else (publicWords.getD (87+limb) 0 : F) := by
  obtain ⟨values,evaluated,attempts⟩ := accepted.2.2.2
  have equations := evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated
  have natEquations : CsrTraceEquations publicWords values := by
    intro index expression found
    exact evaluated_program_satisfies_each_node exact_csr_is_canonical_with_rows evaluated found
  have gate := stable_enabled_gate_value natEquations accepted.1 direction
  have enabled : (values.getD 306 0 : F) = 1 := by
    simp only [List.getD_eq_getElem?_getD,gate,Option.getD_some,Nat.cast_one]
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField,Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField,Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have coefficients := enabled_public_required_coefficients equations enabled
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_public_required_attempts kind bound limb limbBound))
  simp only [publicRequiredAttempt,attempt,csrFieldSum,List.map_cons,List.map_nil,
    List.sum_cons,List.sum_nil,one,one_mul,add_zero] at equation
  by_cases scalar : kind = 0
  · rw [if_pos scalar] at equation ⊢
    by_cases first : limb = 0
    · rw [if_pos first,coefficients 0 (by decide)] at equation
      simpa only [if_pos first,Nat.add_zero] using equation
    · rw [if_neg first,zero] at equation
      simpa only [if_neg first] using equation
  · rw [if_neg scalar,coefficients (1+limb) (by omega)] at equation
    simpa only [if_neg scalar,show 86+(1+limb)=87+limb by omega] using equation

theorem accepted_stable_public_required_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1 ∨ publicWords.getD 83 0 = 2) :
    publicWords.getD 86 0 ≠ 0 ∧ ∃ limb, limb < 7 ∧ publicWords.getD (87+limb) 0 ≠ 0 := by
  constructor
  · obtain ⟨limb,limbBound,nonzero⟩ := accepted_role_difference_nonzero accepted 16 (by decide)
    have binding := accepted_public_required_source accepted direction 0 (by decide) limb limbBound
    simp only [publicRequiredRole,if_true] at binding
    intro magnitudeZero
    rw [magnitudeZero,Nat.cast_zero] at binding
    by_cases first : limb = 0 <;> simp only [first,if_true,if_false] at binding
    · apply nonzero
      simpa only [first] using binding
    · exact nonzero binding
  · obtain ⟨limb,limbBound,nonzero⟩ := accepted_role_difference_nonzero accepted 20 (by decide)
    have binding := accepted_public_required_source accepted direction 1 (by decide) limb limbBound
    simp only [publicRequiredRole,show ¬(1:Nat)=0 by decide,if_false] at binding
    refine ⟨limb,limbBound,?_⟩
    intro sourceZero
    rw [sourceZero,Nat.cast_zero] at binding
    exact nonzero binding


end HegemonCrypto.SmallWood.V8Smz9SemanticStablePublicNonzeroEndpoint
