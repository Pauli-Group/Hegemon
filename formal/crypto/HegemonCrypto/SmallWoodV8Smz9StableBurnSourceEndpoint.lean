import HegemonCrypto.SmallWoodV8Smz9StablePublicNonzeroEndpoint

namespace HegemonCrypto.SmallWood.V8Smz9SemanticStableBurnSourceEndpoint

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoin
open HegemonCrypto.SmallWood.V8Smz9SemanticStablecoinEnabled
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 2000000

def burnIssuerAttempt (limb : Nat) : CsrExecutableAttempt :=
  attempt (19306+limb) 40 limb 1 [(41491+limb,308)] 0

theorem exact_burn_issuer_attempt : ∀ limb, limb < 7 → burnIssuerAttempt limb ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry => entry.family == 40) =
      (List.range 7).map burnIssuerAttempt := by decide
  intro limb bound
  have member : burnIssuerAttempt limb ∈ exactCsrAttempts.filter (fun entry => entry.family == 40) := by
    rw [checked]
    exact List.mem_map.mpr ⟨limb,List.mem_range.mpr bound,rfl⟩
  exact (List.mem_filter.mp member).1

theorem accepted_stable_burn_issuer_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (direction : publicWords.getD 83 0 = 2) :
    ∀ limb, limb < 7 → packedWord packed (41491+limb) = 0 := by
  obtain ⟨values,evaluated,attempts⟩ := accepted.2.2.2
  have equations := evaluated_field_trace_equations exact_csr_is_canonical_with_rows evaluated
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField,Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField,Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have dir : (values.getD 87 0 : F) = 2 := by
    simpa only [expressionField,direction,Nat.cast_ofNat] using equations 87 (.publicWord 83) (by decide)
  have mint : (values.getD 304 0 : F) = 0 := by
    have equation := equations 304 (.selectEqual 87 1 1 0) (by decide)
    simp only [expressionField,dir,one,zero] at equation
    norm_num at equation
    exact equation
  have inactive : (values.getD 308 0 : F) = 1 := by
    simpa only [expressionField,one,mint,sub_zero] using equations 308 (.sub 1 304) (by decide)
  intro limb bound
  have equation := accepted_csr_attempt_field_equality (attempts _ (exact_burn_issuer_attempt limb bound))
  simp only [burnIssuerAttempt,attempt,csrFieldSum,List.map_cons,List.map_nil,List.sum_cons,
    List.sum_nil,inactive,zero,one_mul,add_zero] at equation
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide) equation


end HegemonCrypto.SmallWood.V8Smz9SemanticStableBurnSourceEndpoint
