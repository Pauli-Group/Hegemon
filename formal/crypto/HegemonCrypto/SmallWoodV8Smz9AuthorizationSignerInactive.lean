import HegemonCrypto.SmallWoodV8Smz9AuthorizationRoleNonzero

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical
open HegemonCrypto.SmallWood.V8Smz9AuthorizationOrderTail
open HegemonCrypto.SmallWood.V8Smz9AuthorizationRoleNonzero
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem accepted_inactive_signer_tag_limb_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) {slot limb : Nat}
    (inactive : (projectAuthorization packed).current.signerCount ≤ slot)
    (slotBound : slot < 6) (limbBound : limb < 5) :
    authorizationRawWord packed (196 + 5 * slot + limb) = 0 := by
  let scaled := 1817 + 6 * slot
  let root := 1818 + 6 * slot + limb
  have exactNodes :
      exactNonlinearExpressions[scaled]? = some (.mul 1234 (signerInactiveNode slot)) ∧
      exactNonlinearExpressions[320 + 5 * slot + limb]? =
        some (.witnessRow (196 + 5 * slot + limb)) ∧
      exactNonlinearExpressions[root]? = some (.mul (320 + 5 * slot + limb) scaled) ∧
      root ∈ exactNonlinearRoots := by
    dsimp only [scaled, root]
    interval_cases slot <;> interval_cases limb <;> decide
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := root) (by decide) exactNodes.2.2.2
  have gateOne := authorization_trace_gate_one accepted equations (Or.inr ⟨rfl, mode⟩)
  have inactiveOne := accepted_signer_inactive_trace_one accepted mode equations inactive slotBound
  have scaledValue := equations scaled (.mul 1234 (signerInactiveNode slot)) exactNodes.1
  have tag := equations (320 + 5 * slot + limb)
    (.witnessRow (196 + 5 * slot + limb)) exactNodes.2.1
  have rootValue := equations root (.mul (320 + 5 * slot + limb) scaled) exactNodes.2.2.1
  simp only [expressionField, gateOne, inactiveOne, one_mul] at scaledValue
  simp only [expressionField,
    authorization_lane_zero_word packed (by omega : 196 + 5 * slot + limb < 686)] at tag
  simp only [expressionField, tag, scaledValue, mul_one] at rootValue
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
    (rootValue.symm.trans rootZero)

theorem accepted_inactive_signer_tag_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) {slot : Nat}
    (inactive : (projectAuthorization packed).current.signerCount ≤ slot)
    (slotBound : slot < signerCountMaximum) :
    ZeroWords ((projectAuthorization packed).policySignerTags.getD slot []) := by
  change slot < 6 at slotBound
  rw [project_authorization_signer_tag packed slotBound]
  intro word member
  obtain ⟨limb, limbMember, rfl⟩ := List.mem_map.mp member
  exact accepted_inactive_signer_tag_limb_zero accepted mode inactive slotBound
    (List.mem_range.mp limbMember)

end HegemonCrypto.SmallWood.V8Smz9AuthorizationSignerConstraints
