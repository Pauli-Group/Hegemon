import HegemonCrypto.SmallWoodV8Smz9SourceFullTypedCandidate
import Mathlib.Data.List.Enum

namespace HegemonCrypto.SmallWood.V8Smz9SourceRoleNonzero

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (fieldNormalize fieldSub)
open HegemonCrypto.SmallWood.V8Smz9SourceStableTail
open HegemonCrypto.SmallWood.V8Smz9SourceAuthMaterialization
open HegemonCrypto.SmallWood.V8Smz9SourceTailRolesCanonical
open HegemonCrypto.SmallWood.V8Smz9SourceFullTypedCandidate
open HegemonCrypto.SmallWood.V8Smz9SourceSpongeSegments
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange

set_option maxRecDepth 100000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem nonzero_words_limb (words : List Nat) (bound : words.length ≤ 7)
    (nonzero : NonzeroWords words) : ∃ limb : Fin 7, words.getD limb.val 0 ≠ 0 := by
  obtain ⟨i, hi, nz⟩ := List.exists_mem_iff_getElem.mp nonzero
  refine ⟨⟨i, by omega⟩, ?_⟩
  simpa only [List.getD_eq_getElem words 0 hi] using nz

theorem stable_nonzero_words (words : List Nat) (nonzero : StableNonzeroWords words) :
    NonzeroWords words := by
  obtain ⟨word, member, nz⟩ := List.any_eq_true.mp nonzero
  exact ⟨word, member, of_decide_eq_true nz⟩

theorem slice_readback (witness : V8StablecoinWitness) (start : Nat) (limb : Fin 7) :
    (stableWitnessSlice witness start 7).getD limb.val 0 =
      stableWitnessWord witness (start + limb.val) := by
  rw [List.getD_eq_getElem _ 0 (by simp [stableWitnessSlice])]
  simp only [stableWitnessSlice, List.getElem_map, List.getElem_range]

theorem slice_nonzero_limb (witness : V8StablecoinWitness) (start : Nat)
    (nonzero : StableNonzeroWords (stableWitnessSlice witness start 7)) :
    ∃ limb : Fin 7, stableWitnessWord witness (start + limb.val) ≠ 0 := by
  obtain ⟨limb, nz⟩ := nonzero_words_limb _ (by simp [stableWitnessSlice])
    (stable_nonzero_words _ nonzero)
  exact ⟨limb, by simpa only [slice_readback] using nz⟩

theorem canonical_sub_nonzero (left right : Nat) (hl : left < fieldModulus)
    (hr : right < fieldModulus) (different : left ≠ right) : fieldSub left right ≠ 0 := by
  intro zero
  have cast := field_sub_cast left right (by change right ≤ left + fieldModulus; omega)
  rw [zero, Nat.cast_zero] at cast
  exact different (canonical_nat_cast_injective hl hr (sub_eq_zero.mp cast.symm))

theorem unequal_words_nonzero_sub (left right : List Nat)
    (hl : ExactWords 7 left) (hr : ExactWords 7 right) (different : left ≠ right) :
    ∃ limb : Fin 7, fieldSub (left.getD limb.val 0) (right.getD limb.val 0) ≠ 0 := by
  by_contra absent
  push Not at absent
  apply different
  apply List.ext_getElem (hl.1.trans hr.1.symm)
  intro i hi hj
  have ib : i < 7 := by rwa [hl.1] at hi
  have equal : left.getD i 0 = right.getD i 0 := by
    by_contra differentWords
    exact canonical_sub_nonzero _ _ (auth_exact_words_getD hl i)
      (auth_exact_words_getD hr i) differentWords (absent ⟨i, ib⟩)
  simpa only [List.getD_eq_getElem left 0 hi, List.getD_eq_getElem right 0 hj] using equal

def roleCommitments (witness : V8StablecoinWitness) : List Digest :=
  let config := decodeV8StablecoinConfig witness
  [config.issuerCommitment, config.policyAdminCommitment, config.oracleAuthorityCommitment,
    config.attestationAuthorityCommitment, config.lockedCollateralCommitment]

theorem commitment_list_slice (witness : V8StablecoinWitness) (role : Fin 5) :
    (roleCommitments witness).getD role.val [] =
      stableWitnessSlice witness ([6,24,31,38,48].getD role.val 0) 7 := by
  fin_cases role <;> rfl

theorem commitment_list_readback (witness : V8StablecoinWitness) (role : Fin 5) (limb : Fin 7) :
    ((roleCommitments witness).getD role.val []).getD limb.val 0 =
      sourceCommitmentWord witness role.val limb.val := by
  rw [commitment_list_slice, slice_readback]
  simp only [sourceCommitmentWord, if_pos limb.isLt]

theorem commitment_list_exact (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Fin 5) :
    ExactWords 7 ((roleCommitments witness.stablecoin).getD role.val []) := by
  rw [commitment_list_slice]
  refine ⟨by simp [stableWitnessSlice], ?_⟩
  intro word member
  obtain ⟨i, _, rfl⟩ := List.mem_map.mp member
  exact auth_exact_words_getD (valid_stable_words_exact statement witness valid) _

theorem distinct_list_getD (digests : List Digest) (distinct : DigestListPairwiseDistinct digests)
    (left right : Nat) (hl : left < digests.length) (hr : right < digests.length)
    (ordered : left < right) : digests.getD left [] ≠ digests.getD right [] := by
  have outer := List.forall_mem_zipIdx'.mp (List.all_eq_true.mp distinct) left hl
  have inner := List.forall_mem_zipIdx'.mp (List.all_eq_true.mp outer) right hr
  simp only [if_pos ordered] at inner
  have different := of_decide_eq_true inner
  simpa only [List.getD_eq_getElem digests [] hl, List.getD_eq_getElem digests [] hr] using different

theorem commitment_role_nonzero (witness : V8StablecoinWitness)
    (nonzero : (roleCommitments witness).all
      (fun digest => digest.any (fun word => decide (word ≠ 0))) = true)
    (role : Fin 5) : ∃ limb : Fin 7, sourceCommitmentWord witness role.val limb.val ≠ 0 := by
  have member : (roleCommitments witness).getD role.val [] ∈ roleCommitments witness := by
    rw [List.getD_eq_getElem _ [] (by simp [roleCommitments])]
    exact List.getElem_mem _
  have nz := (List.all_eq_true.mp nonzero) _ member
  rw [commitment_list_slice] at nz
  obtain ⟨limb, nz⟩ := slice_nonzero_limb witness _ nz
  exact ⟨limb, by simpa only [sourceCommitmentWord, if_pos limb.isLt] using nz⟩

theorem difference_role_nonzero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness)
    (distinct : DigestListPairwiseDistinct (roleCommitments witness.stablecoin)) (pair : Fin 10) :
    ∃ limb : Fin 7,
      fieldSub (sourceCommitmentWord witness.stablecoin (sourceStablePairs.getD pair.val (0,0)).1 limb.val)
        (sourceCommitmentWord witness.stablecoin (sourceStablePairs.getD pair.val (0,0)).2 limb.val) ≠ 0 := by
  have geometry : (sourceStablePairs.getD pair.val (0,0)).1 <
        (sourceStablePairs.getD pair.val (0,0)).2 ∧
      (sourceStablePairs.getD pair.val (0,0)).2 < 5 := by
    fin_cases pair <;> decide
  let left : Fin 5 := ⟨(sourceStablePairs.getD pair.val (0,0)).1, by omega⟩
  let right : Fin 5 := ⟨(sourceStablePairs.getD pair.val (0,0)).2, geometry.2⟩
  have different := distinct_list_getD _ distinct left.val right.val
    (by simp [roleCommitments]) (by simp [roleCommitments]) geometry.1
  obtain ⟨limb, nz⟩ := unequal_words_nonzero_sub _ _
    (commitment_list_exact statement witness valid left) (commitment_list_exact statement witness valid right) different
  exact ⟨limb, by simpa only [commitment_list_readback] using nz⟩

theorem stable_role_nonzero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Nat) :
    ∃ limb : Fin 7, sourceStableRoleWord statement.stablecoin witness.stablecoin role limb.val ≠ 0 := by
  by_cases disabled : statement.stablecoin.direction = .disabled
  · exact ⟨0, by simp [sourceStableRoleWord, disabled, sourceUnitWord]⟩
  have transition : exactV8StablecoinEnabledValid (derivedRelationContext statement)
      statement.stablecoin witness.stablecoin := by
    have transition := valid.2.2.2.2
    cases direction : statement.stablecoin.direction with
    | disabled => exact False.elim (disabled direction)
    | mint => simpa only [exactV8SemanticPrimitives, exactV8StableTransition, direction] using transition
    | burn => simpa only [exactV8SemanticPrimitives, exactV8StableTransition, direction] using transition
  obtain ⟨encoding, _, _, _, _, _, intentNZ, _, magnitudePos, magnitudeBound,
    assetEq, _, common, _, _, branch⟩ := transition
  obtain ⟨assetNZ, _, _, _, _, _, _, _, _, _, _, _, _, _, _, commitmentsNZ,
    commitmentsDistinct, _, _⟩ := common
  change (roleCommitments witness.stablecoin).all _ = true at commitmentsNZ
  change DigestListPairwiseDistinct (roleCommitments witness.stablecoin) at commitmentsDistinct
  by_cases low : role < 5
  · obtain ⟨limb, nz⟩ := commitment_role_nonzero _ commitmentsNZ ⟨role, low⟩
    exact ⟨limb, by simpa only [sourceStableRoleWord, if_neg disabled, if_pos low] using nz⟩
  by_cases diff : role < 15
  · obtain ⟨limb, nz⟩ := difference_role_nonzero statement witness valid commitmentsDistinct ⟨role - 5, by omega⟩
    exact ⟨limb, by simpa only [sourceStableRoleWord, if_neg disabled, if_neg low, if_pos diff] using nz⟩
  have normalized (word : Nat) (bound : word < fieldModulus) (nz : word ≠ 0) : fieldNormalize word ≠ 0 := by
    change word % fieldModulus ≠ 0
    rwa [Nat.mod_eq_of_lt bound]
  by_cases issuer : role = 15
  · subst role
    by_cases mint : statement.stablecoin.direction = .mint
    · simp only [mint] at branch
      obtain ⟨limb, nz⟩ := slice_nonzero_limb _ 87 branch.2.1
      exact ⟨limb, by simpa [sourceStableRoleWord, disabled, mint, limb.isLt] using nz⟩
    · exact ⟨0, by simp [sourceStableRoleWord, disabled, mint, sourceUnitWord]⟩
  by_cases magnitude : role = 16
  · subst role
    exact ⟨0, by simpa [sourceStableRoleWord, disabled] using normalized _ (lt_trans magnitudeBound (by decide)) (by omega)⟩
  by_cases numerator : role = 17
  · subst role
    by_cases mint : statement.stablecoin.direction = .mint
    · simp only [mint] at branch
      have nz := branch.1.2.2.2.2.1
      have bound := auth_exact_words_getD (valid_stable_words_exact statement witness valid) 17
      exact ⟨0, by simpa [sourceStableRoleWord, disabled, mint, decodeV8StablecoinConfig, stableWitnessWord] using normalized _ bound nz⟩
    · exact ⟨0, by simp [sourceStableRoleWord, disabled, mint, sourceUnitWord]⟩
  by_cases denominator : role = 18
  · subst role
    by_cases mint : statement.stablecoin.direction = .mint
    · simp only [mint] at branch
      have nz := branch.1.2.2.2.2.2.1
      have bound := auth_exact_words_getD (valid_stable_words_exact statement witness valid) 18
      exact ⟨0, by simpa [sourceStableRoleWord, disabled, mint, decodeV8StablecoinConfig, stableWitnessWord] using normalized _ bound nz⟩
    · exact ⟨0, by simp [sourceStableRoleWord, disabled, mint, sourceUnitWord]⟩
  by_cases asset : role = 19
  · subst role
    have bound : statement.stablecoin.assetId < fieldModulus := by
      rw [assetEq]
      exact auth_exact_words_getD (valid_stable_words_exact statement witness valid) 0
    have nz : statement.stablecoin.assetId ≠ 0 := by rwa [assetEq]
    exact ⟨0, by simpa [sourceStableRoleWord, disabled] using normalized _ bound nz⟩
  by_cases intent : role = 20
  · subst role
    obtain ⟨limb, nz⟩ := nonzero_words_limb _ (by rw [(valid_stable_intent_exact statement witness valid).1]; decide)
      (stable_nonzero_words _ intentNZ)
    exact ⟨limb, by simpa [sourceStableRoleWord, disabled, wordAt] using nz⟩
  exact ⟨0, by simp [sourceStableRoleWord, disabled, low, diff, issuer, magnitude, numerator, denominator, asset, intent, sourceUnitWord]⟩

theorem active_input_spend_nonzero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (input : Nat) (bound : input < 2)
    (active : flagAt statement.inputFlags input = 1) :
    NonzeroWords (witness.inputs.getD input default).spendKey := by
  have shape := valid.2.1.2.2.1 input (by simpa only [inputCount] using bound)
  dsimp only at shape
  have inputBound : input < witness.inputs.length := by rw [valid.2.1.1]; exact bound
  have same (fallback : V8InputWitness) : witness.inputs.getD input fallback = witness.inputs.getD input default := by
    simp [List.getD, inputBound]
  simp only [same] at shape
  have isActive : (witness.inputs.getD input default).active = 1 := shape.1.trans active
  rw [if_neg (by omega)] at shape
  exact shape.2.2.2.1

theorem slot_inactive_after_count (auth : V8AuthorizationWitness) (slot : Nat)
    (after : auth.current.signerCount ≤ slot) : authSlotActive auth slot = 0 := by
  unfold authSlotActive
  have allZero : ∀ offset, offset ∈ List.range (6 - slot) → authSignerFlag auth (slot + offset) = 0 := by
    intro offset _
    have different : auth.current.signerCount ≠ slot + offset + 1 := by omega
    simp [authSignerFlag, authBit, different]
  rw [List.map_eq_replicate_iff.mpr allZero]
  simp

theorem single_slot_inactive (auth : V8AuthorizationWitness) (single : auth.mode = .singleKey) (slot : Nat) :
    authSlotActive auth slot = 0 := by
  simp [authSlotActive, authSignerFlag, single]

theorem typed_source_role_nonzero (statement : V8PublicStatement) (witness : V8Witness)
    (valid : ExactV8RelationSemanticValid statement witness) (role : Nat) :
    ∃ limb : Fin 7, sourceRoleWord statement witness (typedSourceFinals statement witness) role limb.val ≠ 0 := by
  by_cases stable : role < 21
  · obtain ⟨limb, nz⟩ := stable_role_nonzero statement witness valid role
    exact ⟨limb, by simpa only [sourceRoleWord, if_pos stable] using nz⟩
  by_cases spend : role = 21
  · subst role
    by_cases first : flagAt statement.inputFlags 0 = 1
    · obtain ⟨limb, nz⟩ := nonzero_words_limb _
        (by rw [(valid_input_spend_words_exact statement witness valid 0 (by decide)).1]; decide)
        (active_input_spend_nonzero statement witness valid 0 (by decide) first)
      exact ⟨limb, by simpa [sourceRoleWord, selectedTransactionSpendKey, first, wordAt] using nz⟩
    · by_cases second : flagAt statement.inputFlags 1 = 1
      · obtain ⟨limb, nz⟩ := nonzero_words_limb _
          (by rw [(valid_input_spend_words_exact statement witness valid 1 (by decide)).1]; decide)
          (active_input_spend_nonzero statement witness valid 1 (by decide) second)
        exact ⟨limb, by simpa [sourceRoleWord, selectedTransactionSpendKey, first, second, wordAt] using nz⟩
      · exact ⟨0, by simp [sourceRoleWord, first, second, sourceUnitWord]⟩
  have auth := valid.2.2.1.2.2
  by_cases single : witness.authorization.mode = .singleKey
  · by_cases policy : role = 22
    · subst role; exact ⟨0, by simp [sourceRoleWord, single, sourceUnitWord]⟩
    by_cases intent : role = 23
    · subst role; exact ⟨0, by simp [sourceRoleWord, single, sourceUnitWord]⟩
    exact ⟨0, by simp [sourceRoleWord, stable, spend, policy, intent, single_slot_inactive _ single, sourceUnitWord]⟩
  have current : CanonicalAccumulator witness.authorization.current := by
    cases mode : witness.authorization.mode with
    | singleKey => exact False.elim (single mode)
    | approvalStep => simp only [V8AuthorizationValid, mode] at auth; exact auth.2.2.1
    | finalThresholdSpend => simp only [V8AuthorizationValid, mode] at auth; exact auth.2.1
  have tags : CanonicalSignerTags witness.authorization := by
    cases mode : witness.authorization.mode with
    | singleKey => exact False.elim (single mode)
    | approvalStep => simp only [V8AuthorizationValid, mode] at auth; exact auth.2.2.2.2.1
    | finalThresholdSpend => simp only [V8AuthorizationValid, mode] at auth; exact auth.2.2.2.1
  by_cases policy : role = 22
  · subst role
    obtain ⟨limb, nz⟩ := nonzero_words_limb _ (by rw [current.1.1]; decide) current.2.1
    exact ⟨limb, by rwa [typed_source_policy_role_is_current statement witness valid single]⟩
  by_cases intent : role = 23
  · subst role
    obtain ⟨limb, nz⟩ := nonzero_words_limb _ (by rw [current.2.2.1.1]; decide) current.2.2.2.1
    exact ⟨limb, by simpa [sourceRoleWord, single, wordAt] using nz⟩
  by_cases signer : role < 30
  · by_cases active : authSlotActive witness.authorization (role - 24) = 1
    · have inCount : role - 24 < witness.authorization.current.signerCount := by
        by_contra after
        have zero := slot_inactive_after_count witness.authorization (role - 24) (by omega)
        omega
      obtain ⟨limb, nz⟩ := nonzero_words_limb _
        (by rw [(tags.2.1 (role - 24) (by dsimp [signerCountMaximum]; omega)).1]; decide)
        (tags.2.2.1 (role - 24) inCount)
      exact ⟨limb, by simpa only [sourceRoleWord, if_neg stable, if_neg spend, if_neg policy, if_neg intent, if_pos signer, if_pos active, wordAt] using nz⟩
    · exact ⟨0, by simp [sourceRoleWord, stable, spend, policy, intent, signer, active, sourceUnitWord]⟩
  exact ⟨0, by simp [sourceRoleWord, stable, spend, policy, intent, signer, sourceUnitWord]⟩


end HegemonCrypto.SmallWood.V8Smz9SourceRoleNonzero
