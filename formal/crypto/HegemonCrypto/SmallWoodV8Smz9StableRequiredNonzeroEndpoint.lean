import HegemonCrypto.SmallWoodV8Smz9StableRolesEndpoint
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableRequiredNonzeroEndpoint

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

def mintRequiredRole (i : Nat) : Nat := if i = 0 then 15 else 16+i
def mintRequiredSource (i limb : Nat) : Nat := if i = 0 then 41491+limb else 41424+i

def mintRequiredAttempt (i limb : Nat) : CsrExecutableAttempt :=
  let role := mintRequiredRole i
  attempt (19344+7*role+limb) 47 (7*role+limb) 0
    [(41536+64*limb+role,1),(mintRequiredSource i limb,if i = 0 ∨ limb = 0 then 323 else 0)]
    (if limb = 0 then 308 else 0)

theorem exact_mint_required_attempts : ∀ i, i < 3 → ∀ limb, limb < 7 →
    mintRequiredAttempt i limb ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 47 &&
      (entry.localIndex / 7 == 15 || entry.localIndex / 7 == 17 || entry.localIndex / 7 == 18)) =
      (List.range 3).flatMap (fun i => (List.range 7).map (mintRequiredAttempt i)) := by decide
  intro i bound limb limbBound
  have filtered : mintRequiredAttempt i limb ∈ exactCsrAttempts.filter (fun entry => entry.family == 47 &&
      (entry.localIndex / 7 == 15 || entry.localIndex / 7 == 17 || entry.localIndex / 7 == 18)) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨i,List.mem_range.mpr bound,
      List.mem_map.mpr ⟨limb,List.mem_range.mpr limbBound,rfl⟩⟩
  exact (List.mem_filter.mp filtered).1

theorem accepted_mint_required_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) (i : Nat) (bound : i < 3)
    (limb : Nat) (limbBound : limb < 7) :
    (packed.getD (41536+64*limb+mintRequiredRole i) 0 : F) =
      if i = 0 ∨ limb = 0 then (packed.getD (mintRequiredSource i limb) 0 : F) else 0 := by
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
  have inactive : (values.getD 308 0 : F) = 0 := by
    simpa only [expressionField,one,mint,sub_self] using equations 308 (.sub 1 304) (by decide)
  have equation := accepted_csr_attempt_field_equality (attempts _ (exact_mint_required_attempts i bound limb limbBound))
  have target : (values.getD (mintRequiredAttempt i limb).targetRoot 0 : F) = 0 := by
    by_cases first : limb = 0 <;> simp only [mintRequiredAttempt,attempt,first,if_true,if_false,inactive,zero]
  rw [target] at equation
  by_cases present : i = 0 ∨ limb = 0
  · simp only [mintRequiredAttempt,attempt,present,if_true,csrFieldSum,List.map_cons,List.map_nil,
      List.sum_cons,List.sum_nil,one,negative,one_mul,neg_one_mul,add_zero] at equation
    rw [if_pos present]
    exact add_neg_eq_zero.mp equation
  · simp only [mintRequiredAttempt,attempt,present,if_false,csrFieldSum,List.map_cons,List.map_nil,
      List.sum_cons,List.sum_nil,one,zero,one_mul,zero_mul,add_zero] at equation
    rw [if_neg present]
    exact equation

theorem accepted_stable_mint_required_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 1) :
    (∃ limb, limb < 7 ∧ packedWord packed (41491+limb) ≠ 0) ∧
      packedWord packed 41425 ≠ 0 ∧ packedWord packed 41426 ≠ 0 := by
  have required (i : Nat) (bound : i < 3) :
      ∃ limb, limb < 7 ∧ (i = 0 ∨ limb = 0) ∧ packedWord packed (mintRequiredSource i limb) ≠ 0 := by
    obtain ⟨limb,limbBound,nonzero⟩ := accepted_role_difference_nonzero accepted (mintRequiredRole i)
      (by unfold mintRequiredRole; split <;> omega)
    have binding := accepted_mint_required_source accepted direction i bound limb limbBound
    by_cases present : i = 0 ∨ limb = 0
    · rw [if_pos present] at binding
      refine ⟨limb,limbBound,present,?_⟩
      intro sourceZero
      simp only [packedWord] at sourceZero
      rw [sourceZero,Nat.cast_zero] at binding
      exact nonzero binding
    · rw [if_neg present] at binding
      exact False.elim (nonzero binding)
  obtain ⟨limb,limbBound,_,nonzero⟩ := required 0 (by decide)
  obtain ⟨numerator,numeratorBound,numeratorPresent,numeratorNonzero⟩ := required 1 (by decide)
  obtain ⟨denominator,denominatorBound,denominatorPresent,denominatorNonzero⟩ := required 2 (by decide)
  refine ⟨⟨limb,limbBound,?_⟩,?_,?_⟩
  · simpa only [mintRequiredSource,if_true] using nonzero
  · simpa only [mintRequiredSource,show ¬(1:Nat) = 0 by decide,if_false,Nat.reduceAdd] using numeratorNonzero
  · simpa only [mintRequiredSource,show ¬(2:Nat) = 0 by decide,if_false,Nat.reduceAdd] using denominatorNonzero


end HegemonCrypto.SmallWood.V8Smz9SemanticStableRequiredNonzeroEndpoint
