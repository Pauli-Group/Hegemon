import HegemonCrypto.SmallWoodV8Smz9StableRolesEndpoint
import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorizationNonSingle
import HegemonCrypto.SmallWoodV8Smz9SemanticInactiveWitness
import HegemonCrypto.SmallWoodV8Smz9AuthorizationOrderTail
import Mathlib.Tactic.LinearCombination

namespace HegemonCrypto.SmallWood.V8Smz9AuthorizationRoleNonzero

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (CsrExecutableAttempt fieldSub)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticStableRolesEndpoint
open HegemonCrypto.SmallWood.V8Smz9AuthorizationCanonical
open HegemonCrypto.SmallWood.V8Smz9AuthorizationOrderTail
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

def authorizationRoleAttempt (offset limb : Nat) : CsrExecutableAttempt :=
  let condition := 22 + offset
  attempt (19344 + 7 * condition + limb) 47 (7 * condition + limb) 0
    [(41536 + 64 * limb + condition, 1),
      (64 * (138 + 7 * offset + limb), 158),
      (5952, if limb = 0 then 265 else 0),
      (6016, if limb = 0 then 265 else 0)]
    (if limb = 0 then 1 else 0)

theorem exact_authorization_role_attempts : ∀ offset, offset < 2 → ∀ limb, limb < 7 →
    authorizationRoleAttempt offset limb ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry =>
      entry.family == 47 && 154 ≤ entry.localIndex && entry.localIndex < 168) =
      (List.range 2).flatMap (fun offset =>
        (List.range 7).map (authorizationRoleAttempt offset)) := by decide
  intro offset offsetBound limb limbBound
  have member : authorizationRoleAttempt offset limb ∈ exactCsrAttempts.filter (fun entry =>
      entry.family == 47 && 154 ≤ entry.localIndex && entry.localIndex < 168) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨offset, List.mem_range.mpr offsetBound,
      List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩⟩
  exact (List.mem_filter.mp member).1

theorem accepted_authorization_role_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    {offset limb : Nat} (offsetBound : offset < 2) (limbBound : limb < 7) :
    (packed.getD (41536 + 64 * limb + (22 + offset)) 0 : F) =
      (authorizationRawWord packed (138 + 7 * offset + limb) : F) := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zero, one, zero_sub] using
      equations 158 (.sub 0 1) (by decide)
  have positive : (values.getD 265 0 : F) = 1 := by
    simpa only [expressionField, zero, negative, zero_sub, neg_neg] using
      equations 265 (.sub 0 158) (by decide)
  have modeSumNat := accepted_non_single_mode_sum accepted mode
  have modeSum : (packed.getD 5952 0 : F) + (packed.getD 6016 0 : F) = 1 := by
    have casted := congrArg (fun value : Nat => (value : F)) modeSumNat
    simpa only [authorizationWord,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.authorizationModeRow,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.zero_add, packedWord, Nat.cast_add, Nat.cast_one] using casted
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_authorization_role_attempts offset offsetBound limb limbBound))
  by_cases first : limb = 0
  · subst limb
    have equality :
        (packed.getD (41536 + 64 * 0 + (22 + offset)) 0 : F) =
          (packed.getD (64 * (138 + 7 * offset + 0)) 0 : F) := by
      simp only [authorizationRoleAttempt, attempt, if_true, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
        one, negative, positive, one_mul, neg_one_mul, add_zero] at equation
      linear_combination equation - modeSum
    simpa only [authorizationRawWord, packedWord, Nat.mul_comm] using equality
  · have equality :
        (packed.getD (41536 + 64 * limb + (22 + offset)) 0 : F) =
          (packed.getD (64 * (138 + 7 * offset + limb)) 0 : F) := by
      simp only [authorizationRoleAttempt, attempt, first, if_false, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil,
        one, negative, zero, one_mul, neg_one_mul, zero_mul, add_zero] at equation
      exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using equation)
    simpa only [authorizationRawWord, packedWord, Nat.mul_comm] using equality

theorem accepted_non_single_policy_root_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    NonzeroWords (projectAuthorization packed).current.policyRoot := by
  obtain ⟨limb, limbBound, differenceNonzero⟩ :=
    accepted_role_difference_nonzero accepted 22 (by decide)
  have binding := accepted_authorization_role_source accepted mode (offset := 0)
    (limb := limb) (by decide) limbBound
  have rawNonzero : authorizationRawWord packed (138 + limb) ≠ 0 := by
    intro zeroRaw
    rw [zeroRaw, Nat.cast_zero] at binding
    exact differenceNonzero binding
  have source := accepted_current_opening_source_word accepted (word := limb) (by omega)
  have sourceNonzero : spongeSourceWord packed 98 limb ≠ 0 := by
    rw [source]
    simpa only [Nat.zero_add] using rawNonzero
  refine ⟨spongeSourceWord packed 98 limb, ?_, sourceNonzero⟩
  simp only [projectAuthorization, projectAccumulator]
  exact List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩

theorem accepted_non_single_intent_digest_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) :
    NonzeroWords (projectAuthorization packed).current.intentDigest := by
  obtain ⟨limb, limbBound, differenceNonzero⟩ :=
    accepted_role_difference_nonzero accepted 23 (by decide)
  have binding := accepted_authorization_role_source accepted mode (offset := 1)
    (limb := limb) (by decide) limbBound
  have rawNonzero : authorizationRawWord packed (145 + limb) ≠ 0 := by
    intro zeroRaw
    have address : 138 + 7 * 1 + limb = 145 + limb := by omega
    rw [address, zeroRaw, Nat.cast_zero] at binding
    exact differenceNonzero binding
  have source := accepted_current_opening_source_word accepted (word := 7 + limb) (by omega)
  have sourceNonzero : spongeSourceWord packed 98 (7 + limb) ≠ 0 := by
    rw [source]
    have address : 138 + (7 + limb) = 145 + limb := by omega
    rw [address]
    exact rawNonzero
  refine ⟨spongeSourceWord packed 98 (7 + limb), ?_, sourceNonzero⟩
  simp only [projectAuthorization, projectAccumulator]
  exact List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩

def authorizationSignerRoleAttempt (slot limb : Nat) : CsrExecutableAttempt :=
  let condition := 24 + slot
  attempt (19344 + 7 * condition + limb) 47 (7 * condition + limb) 0
    ([(41536 + 64 * limb + condition, 1)] ++
      (if limb < 5 then [(64 * (196 + 5 * slot + limb), 158)] else []) ++
      (List.range (6 - slot)).map (fun index =>
        (64 * (176 + slot + index), if limb = 0 then 265 else 0)))
    (if limb = 0 then 1 else 0)

theorem exact_authorization_signer_role_attempts : ∀ slot, slot < 6 → ∀ limb, limb < 7 →
    authorizationSignerRoleAttempt slot limb ∈ exactCsrAttempts := by
  have checked : exactCsrAttempts.filter (fun entry =>
      entry.family == 47 && 168 ≤ entry.localIndex && entry.localIndex < 210) =
      (List.range 6).flatMap (fun slot =>
        (List.range 7).map (authorizationSignerRoleAttempt slot)) := by decide
  intro slot slotBound limb limbBound
  have member : authorizationSignerRoleAttempt slot limb ∈ exactCsrAttempts.filter (fun entry =>
      entry.family == 47 && 168 ≤ entry.localIndex && entry.localIndex < 210) := by
    rw [checked]
    exact List.mem_flatMap.mpr ⟨slot, List.mem_range.mpr slotBound,
      List.mem_map.mpr ⟨limb, List.mem_range.mpr limbBound, rfl⟩⟩
  exact (List.mem_filter.mp member).1

theorem accepted_authorization_signer_role_source {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey)
    {slot limb : Nat} (active : slot < (projectAuthorization packed).current.signerCount)
    (slotBound : slot < 6) (limbBound : limb < 7) :
    (packed.getD (41536 + 64 * limb + (24 + slot)) 0 : F) =
      if limb < 5 then (authorizationRawWord packed (196 + 5 * slot + limb) : F) else 0 := by
  obtain ⟨values, equations, attempts⟩ := accepted_csr_field_trace accepted
  have zero : (values.getD 0 0 : F) = 0 := by
    simpa only [expressionField, Nat.cast_zero] using equations 0 (.constant 0) (by decide)
  have one : (values.getD 1 0 : F) = 1 := by
    simpa only [expressionField, Nat.cast_one] using equations 1 (.constant 1) (by decide)
  have negative : (values.getD 158 0 : F) = -1 := by
    simpa only [expressionField, zero, one, zero_sub] using equations 158 (.sub 0 1) (by decide)
  have positive : (values.getD 265 0 : F) = 1 := by
    simpa only [expressionField, zero, negative, zero_sub, neg_neg] using
      equations 265 (.sub 0 158) (by decide)
  have suffixNat := (accepted_signer_suffix_sum accepted mode slotBound).1 active
  have suffixField : ((List.range (6 - slot)).map (fun index =>
      (packed.getD (64 * (176 + slot + index)) 0 : F))).sum = 1 := by
    have casted := congrArg (fun value : Nat => (value : F)) suffixNat
    simp only [authorizationRawSum, authorizationRawWord, packedWord] at casted
    rw [Nat.cast_list_sum] at casted
    simpa only [Nat.cast_one, List.map_map, Function.comp_def, Nat.mul_comm,
      Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using casted
  have positiveSuffix :
      (List.map
        ((fun term : Nat × Nat =>
          (values.getD term.2 0 : F) * (packed.getD term.1 0 : F)) ∘ fun index =>
            (64 * (176 + slot + index), 265))
        (List.range (6 - slot))).sum =
      ((List.range (6 - slot)).map (fun index =>
        (packed.getD (64 * (176 + slot + index)) 0 : F))).sum := by
    change ((List.range (6 - slot)).map (fun index =>
      (values.getD 265 0 : F) *
        (packed.getD (64 * (176 + slot + index)) 0 : F))).sum = _
    simp only [positive, one_mul]
  have zeroSuffix :
      (List.map
        ((fun term : Nat × Nat =>
          (values.getD term.2 0 : F) * (packed.getD term.1 0 : F)) ∘ fun index =>
            (64 * (176 + slot + index), 0))
        (List.range (6 - slot))).sum = 0 := by
    change ((List.range (6 - slot)).map (fun index =>
      (values.getD 0 0 : F) *
        (packed.getD (64 * (176 + slot + index)) 0 : F))).sum = 0
    simp only [zero, zero_mul, List.sum_map_zero]
  have equation := accepted_csr_attempt_field_equality
    (attempts _ (exact_authorization_signer_role_attempts slot slotBound limb limbBound))
  by_cases tag : limb < 5
  · rw [if_pos tag]
    by_cases first : limb = 0
    · subst limb
      have equality :
          (packed.getD (41536 + 64 * 0 + (24 + slot)) 0 : F) =
            (packed.getD (64 * (196 + 5 * slot + 0)) 0 : F) := by
        simp only [authorizationSignerRoleAttempt, attempt, show (0 : Nat) < 5 by decide,
          if_true, List.cons_append, List.nil_append, csrFieldSum, List.map_cons,
          List.map_map, List.sum_cons, one, negative, one_mul, neg_one_mul,
          add_zero] at equation
        rw [positiveSuffix] at equation
        linear_combination equation - suffixField
      simpa only [authorizationRawWord, packedWord, Nat.mul_comm] using equality
    · have equality :
          (packed.getD (41536 + 64 * limb + (24 + slot)) 0 : F) =
            (packed.getD (64 * (196 + 5 * slot + limb)) 0 : F) := by
        simp only [authorizationSignerRoleAttempt, attempt, tag, first, if_true, if_false,
          List.cons_append, List.nil_append, csrFieldSum, List.map_cons, List.map_map,
          List.sum_cons, one, negative, zero, one_mul, neg_one_mul] at equation
        rw [zeroSuffix] at equation
        simp only [add_zero] at equation
        exact sub_eq_zero.mp (by simpa only [sub_eq_add_neg] using equation)
      simpa only [authorizationRawWord, packedWord, Nat.mul_comm] using equality
  · rw [if_neg tag]
    have first : limb ≠ 0 := by omega
    simp only [authorizationSignerRoleAttempt, attempt, tag, first, if_false,
      List.cons_append, List.nil_append, csrFieldSum, List.map_cons, List.map_map,
      List.sum_cons, one, zero] at equation
    rw [zeroSuffix] at equation
    simp only [add_zero] at equation
    simpa only [one_mul] using equation

theorem accepted_active_signer_tag_nonzero {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed ≠ .singleKey) {slot : Nat}
    (active : slot < (projectAuthorization packed).current.signerCount) :
    NonzeroWords ((projectAuthorization packed).policySignerTags.getD slot []) := by
  have slotBound : slot < 6 := by
    have bound := (accepted_non_single_signer_count_bounds accepted mode).2
    change _ ≤ 6 at bound
    omega
  obtain ⟨limb, limbBound, differenceNonzero⟩ :=
    accepted_role_difference_nonzero accepted (24 + slot) (by omega)
  have binding := accepted_authorization_signer_role_source accepted mode active slotBound limbBound
  have limbTag : limb < 5 := by
    by_contra outside
    rw [if_neg (by omega)] at binding
    exact differenceNonzero binding
  rw [if_pos limbTag] at binding
  have rawNonzero : authorizationRawWord packed (196 + 5 * slot + limb) ≠ 0 := by
    intro zeroRaw
    rw [zeroRaw, Nat.cast_zero] at binding
    exact differenceNonzero binding
  rw [project_authorization_signer_tag packed slotBound]
  refine ⟨authorizationRawWord packed (196 + 5 * slot + limb), ?_, rawNonzero⟩
  exact List.mem_map.mpr ⟨limb, List.mem_range.mpr limbTag, rfl⟩


end HegemonCrypto.SmallWood.V8Smz9AuthorizationRoleNonzero
