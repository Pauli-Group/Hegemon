import HegemonCrypto.SmallWoodV8Smz9AuthorizationRoleNonzero

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationNextCanonical

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

theorem accepted_current_canonical_for_next {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    CanonicalAccumulator (projectAuthorization packed).current := by
  have shape := accepted_non_single_current_shape accepted mode
  exact ⟨shape.1, accepted_non_single_policy_root_nonzero accepted mode,
    shape.2.1, accepted_non_single_intent_digest_nonzero accepted mode,
    shape.2.2.1, accepted_threshold_le_signer_count accepted mode,
    shape.2.2.2.1, accepted_current_approval_count_le_signer accepted mode,
    shape.2.2.2.2.2.1, shape.2.2.2.2.2.2.1, shape.2.2.2.2.2.2.2,
    (by intro slot inactive bound; exact accepted_current_bitmap_inactive_zero accepted mode inactive bound)⟩

def membershipScaledNode (slot : Nat) : Nat := 1694 + 5 * slot
def inactiveMembershipRoot (slot : Nat) : Nat := 1751 + 11 * slot

/-- An approval membership flag cannot select a slot outside the source-derived
signer prefix.  This is the missing range half of the one-hot membership rule. -/
theorem accepted_approval_inactive_membership_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) {slot : Nat}
    (inactive : (projectAuthorization packed).current.signerCount ≤ slot)
    (slotBound : slot < signerCountMaximum) :
    authorizationRawWord packed (226 + slot) = 0 := by
  change slot < 6 at slotBound
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by
    simp only [mode]
    decide
  have exactNodes :
      exactNonlinearExpressions[350 + slot]? = some (.witnessRow (226 + slot)) ∧
      exactNonlinearExpressions[membershipScaledNode slot]? = some (.mul 217 (350 + slot)) ∧
      exactNonlinearExpressions[inactiveMembershipRoot slot]? =
        some (.mul (signerInactiveNode slot) (membershipScaledNode slot)) ∧
      inactiveMembershipRoot slot ∈ exactNonlinearRoots := by
    interval_cases slot <;> decide
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := inactiveMembershipRoot slot) (by decide) exactNodes.2.2.2
  have gateOne := authorization_trace_gate_one accepted equations (Or.inl ⟨rfl, mode⟩)
  have inactiveOne := accepted_signer_inactive_trace_one accepted notSingle equations
    inactive slotBound
  have membership := equations (350 + slot) (.witnessRow (226 + slot)) exactNodes.1
  have scaled := equations (membershipScaledNode slot) (.mul 217 (350 + slot)) exactNodes.2.1
  have root := equations (inactiveMembershipRoot slot)
    (.mul (signerInactiveNode slot) (membershipScaledNode slot)) exactNodes.2.2.1
  simp only [expressionField,
    authorization_lane_zero_word packed (by omega : 226 + slot < 686)] at membership
  simp only [expressionField, gateOne, membership, one_mul] at scaled
  simp only [expressionField, inactiveOne, scaled, one_mul] at root
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _) (by decide)
    (root.symm.trans rootZero)

theorem accepted_approval_next_bitmap_inactive_zero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) {slot : Nat}
    (inactive : (projectAuthorization packed).next.signerCount ≤ slot)
    (slotBound : slot < signerCountMaximum) :
    wordAt (projectAuthorization packed).next.approvedSlots slot = 0 := by
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by
    simp only [mode]
    decide
  have shared := accepted_approval_shared_opening_fields accepted mode
  have currentInactive : (projectAuthorization packed).current.signerCount ≤ slot := by
    rw [← shared.2.2.2]
    exact inactive
  have currentZero := accepted_current_bitmap_inactive_zero accepted notSingle currentInactive slotBound
  have membershipZero := accepted_approval_inactive_membership_zero accepted mode currentInactive slotBound
  have step := accepted_approval_projected_bitmap_step accepted mode (by
    change slot < 6 at slotBound
    exact slotBound)
  omega

theorem accepted_approval_next_approval_count_sum {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    (projectAuthorization packed).next.approvalCount =
      (projectAuthorization packed).next.approvedSlots.sum := by
  have countSource := accepted_next_opening_source_word accepted (word := 16) (by decide)
  have slots : (List.range 6).map (fun slot => spongeSourceWord packed 101 (17 + slot)) =
      (List.range 6).map (fun slot => authorizationRawWord packed (162 + slot)) := by
    apply List.map_congr_left
    intro slot member
    have source := accepted_next_opening_source_word accepted (word := 17 + slot)
      (by have := List.mem_range.mp member; omega)
    have address : nextOpeningRawRow (17 + slot) = 162 + slot := by
      simp only [nextOpeningRawRow, if_neg (by omega : ¬17 + slot < 16)]
      omega
    simpa only [address] using source
  simp only [projectAuthorization, mode, if_true, projectAccumulator]
  rw [countSource, slots]
  exact accepted_next_raw_count accepted mode

theorem six_list_sum_le_count (words : List Nat) (length : words.length = 6)
    (count : Nat) (countBound : count ≤ 6)
    (boolean : ∀ slot, slot < 6 → BooleanWord (wordAt words slot))
    (tail : ∀ slot, count ≤ slot → slot < 6 → wordAt words slot = 0) :
    words.sum ≤ count := by
  have enumeration : (List.range 6).map (wordAt words) = words := by
    apply List.ext_getElem
    · simp [length]
    · intro index leftBound rightBound
      simp only [List.getElem_map, List.getElem_range, wordAt]
      exact List.getD_eq_getElem _ _ rightBound
  have source := boolean_six_sum_le_count count (wordAt words) countBound boolean tail
  have mapped : ((List.range 6).map (wordAt words)).sum ≤ count := by
    simpa only [List.range_succ, List.range_zero, List.map_append, List.map_cons,
      List.map_nil, List.sum_append, List.sum_cons, List.sum_nil, Nat.add_zero,
      zero_add, Nat.add_assoc] using source
  simpa only [enumeration] using mapped

theorem accepted_approval_next_count_le_signer {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    (projectAuthorization packed).next.approvalCount ≤
      (projectAuthorization packed).next.signerCount := by
  rw [accepted_approval_next_approval_count_sum accepted mode]
  have length : (projectAuthorization packed).next.approvedSlots.length = 6 := by
    simp [projectAuthorization, projectAccumulator, mode]
  have boolean : ∀ slot, slot < 6 →
      BooleanWord (wordAt (projectAuthorization packed).next.approvedSlots slot) := by
    intro slot bound
    rw [accepted_next_bitmap_word accepted mode bound]
    exact accepted_next_bitmap_boolean accepted mode bound
  have tail : ∀ slot, (projectAuthorization packed).next.signerCount ≤ slot → slot < 6 →
      wordAt (projectAuthorization packed).next.approvedSlots slot = 0 := by
    intro slot inactive bound
    exact accepted_approval_next_bitmap_inactive_zero accepted mode inactive bound
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by
    simp only [mode]
    decide
  have shared := accepted_approval_shared_opening_fields accepted mode
  have currentSignerBound := (accepted_non_single_signer_count_bounds accepted notSingle).2
  have signerBound : (projectAuthorization packed).next.signerCount ≤ signerCountMaximum := by
    rw [shared.2.2.2]
    exact currentSignerBound
  have countBound : (projectAuthorization packed).next.signerCount ≤ 6 := by
    simpa only [signerCountMaximum] using signerBound
  exact six_list_sum_le_count _ length _ countBound boolean tail

theorem accepted_approval_canonical_next_accumulator {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    CanonicalAccumulator (projectAuthorization packed).next := by
  have notSingle : projectAuthorizationMode packed ≠ .singleKey := by
    simp only [mode]
    decide
  have current := accepted_current_canonical_for_next accepted notSingle
  have shared := accepted_approval_shared_opening_fields accepted mode
  rcases current with ⟨policyExact, policyNonzero, intentExact, intentNonzero,
    thresholdPositive, thresholdLeSigner, signerBound, _, _, _, _, _⟩
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_,
    accepted_approval_next_count_le_signer accepted mode, ?_, ?_,
    accepted_approval_next_approval_count_sum accepted mode, ?_⟩
  · rw [shared.1]
    exact policyExact
  · rw [shared.1]
    exact policyNonzero
  · rw [shared.2.1]
    exact intentExact
  · rw [shared.2.1]
    exact intentNonzero
  · rw [shared.2.2.1]
    exact thresholdPositive
  · rw [shared.2.2.1, shared.2.2.2]
    exact thresholdLeSigner
  · rw [shared.2.2.2]
    exact signerBound
  · simp [projectAuthorization, projectAccumulator, mode, signerCountMaximum]
  · intro slot bound
    change slot < 6 at bound
    rw [accepted_next_bitmap_word accepted mode bound]
    exact accepted_next_bitmap_boolean accepted mode bound
  · intro slot inactive bound
    exact accepted_approval_next_bitmap_inactive_zero accepted mode inactive bound


end HegemonCrypto.SmallWood.V8Smz9AuthorizationNextCanonical
