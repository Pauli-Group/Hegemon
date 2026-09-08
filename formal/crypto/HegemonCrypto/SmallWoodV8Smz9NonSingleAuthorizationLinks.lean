import HegemonCrypto.SmallWoodV8Smz9InputNonSingleModes
import HegemonCrypto.SmallWoodV8Smz9InputAuthorizationKeys
import HegemonCrypto.SmallWoodV8Smz9AuthorizationDigestCopies
import HegemonCrypto.SmallWoodV8Smz9AccumulatorSource
import HegemonCrypto.SmallWoodV8Smz9ValueLockSource
import HegemonCrypto.SmallWoodV8Smz9SemanticAuthorizationNonSingle

namespace HegemonCrypto.SmallWood.V8Smz9NonSingleAuthorizationLinks

open Hegemon.Transaction
open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram (FieldExpression)
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (rawIndex)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticInactiveWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorization
open HegemonCrypto.SmallWood.V8Smz9SemanticAuthorizationNonSingle
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointInputModes
open HegemonCrypto.SmallWood.V8Smz9InputNonSingleModes
open HegemonCrypto.SmallWood.V8Smz9InputAuthorizationKeys
open HegemonCrypto.SmallWood.V8Smz9AuthorizationDigestCopies
open HegemonCrypto.SmallWood.V8Smz9AccumulatorSource
open HegemonCrypto.SmallWood.V8Smz9ValueLockSource
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrf
open HegemonCrypto.SmallWood.V8Smz9SemanticEndpointPrfLegacy
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials (expressionField)

set_option maxHeartbeats 1000000
set_option maxRecDepth 1000000
set_option Elab.async false

theorem authorization_raw_word_eq_packed (packed : List Nat) (row : Nat) :
    authorizationRawWord packed row = packedWord packed (rawIndex row) := by
  simp only [authorizationRawWord, rawIndex,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
    Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor, Nat.zero_add]

def authorizationExactDigest (packed : List Nat) (digest : Nat) : List Nat :=
  if digest = 0 then exactV8AccumulatorDigest (projectAccumulator packed 98)
  else if digest = 1 then exactV8AccumulatorDigest (projectAccumulator packed 101)
  else exactV8ValueLockDigest (projectAccumulator packed 98)

theorem accepted_authorization_digest_exact_list {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (digest : Fin 3) :
    (List.range 7).map (fun limb => authorizationRawWord packed (110 + 7 * digest.val + limb)) =
      authorizationExactDigest packed digest.val := by
  rw [accepted_authorization_digest_copy_list accepted digest]
  fin_cases digest
  · simpa only [authorizationDigestCall, authorizationExactDigest, accumulatorCall,
      Nat.mul_zero, Nat.add_zero, if_true] using
      accepted_accumulator_digest_eq_exact accepted ⟨0, by decide⟩
  · simpa only [authorizationDigestCall, authorizationExactDigest, accumulatorCall,
      Nat.mul_one, Nat.reduceAdd, Nat.one_ne_zero, if_false, if_true] using
      accepted_accumulator_digest_eq_exact accepted ⟨1, by decide⟩
  · exact accepted_value_lock_digest_eq_exact accepted

theorem accepted_authorization_digest_exact_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (digest : Fin 3) (limb : Fin 7) :
    authorizationRawWord packed (110 + 7 * digest.val + limb.val) =
      (authorizationExactDigest packed digest.val).getD limb.val 0 := by
  have result := congrArg (fun words : List Nat => words.getD limb.val 0)
    (accepted_authorization_digest_exact_list accepted digest)
  simpa [List.getD_eq_getElem?_getD, limb.isLt] using result

theorem accepted_authorization_digest_exact_key {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) (digest : Fin 3) :
    (List.range 4).map (fun limb => authorizationRawWord packed (110 + 7 * digest.val + limb)) =
      (authorizationExactDigest packed digest.val).take 4 := by
  exact congrArg (List.take 4) (accepted_authorization_digest_exact_list accepted digest)

theorem accepted_approval_input_scalar {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    (input : Fin 2) (active : publicWords.getD input.val 0 = 1) :
    authorizationRawWord packed (95 + input.val) =
      if input.val = 0 then (exactV8AccumulatorDigest (projectAccumulator packed 98)).getD 4 0
      else (exactV8TransactionPrf (prfWords packed)).getD 0 0 := by
  have source := accepted_active_approval_input_authorization_word accepted mode input ⟨0, by decide⟩ active
  simp only [inputAuthOutRow, inputAuthApprovalRow, if_true, Nat.add_zero] at source
  by_cases first : input.val = 0
  · rw [if_pos first] at source ⊢
    exact source.trans (accepted_authorization_digest_exact_word accepted ⟨0, by decide⟩ ⟨4, by decide⟩)
  · rw [if_neg first] at source ⊢
    exact source.trans (accepted_legacy_word_eq_exact_prf accepted ⟨0, by decide⟩)

theorem accepted_final_input_scalar {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend)
    (input : Fin 2) (active : publicWords.getD input.val 0 = 1) :
    authorizationRawWord packed (95 + input.val) =
      if input.val = 0 then (exactV8ValueLockDigest (projectAccumulator packed 98)).getD 4 0
      else (exactV8AccumulatorDigest (projectAccumulator packed 98)).getD 4 0 := by
  have source := accepted_active_final_input_authorization_word accepted mode input ⟨0, by decide⟩ active
  simp only [inputAuthOutRow, inputAuthFinalRow, if_true, Nat.add_zero] at source
  by_cases first : input.val = 0
  · rw [if_pos first] at source ⊢
    exact source.trans (accepted_authorization_digest_exact_word accepted ⟨2, by decide⟩ ⟨4, by decide⟩)
  · rw [if_neg first] at source ⊢
    exact source.trans (accepted_authorization_digest_exact_word accepted ⟨0, by decide⟩ ⟨4, by decide⟩)

theorem admitted_approval_input_effective_prf {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input = 1) :
    packedWord packed (rawIndex (95 + input)) = effectiveInputAuthorizationPrf
      exactV8SemanticPrimitives (projectTypedWitness statement packed) input := by
  have result := accepted_approval_input_scalar domain.2.2 mode ⟨input, bound⟩
    ((admitted_public_input_flag domain bound).trans active)
  rw [← authorization_raw_word_eq_packed]
  unfold effectiveInputAuthorizationPrf
  dsimp only
  rw [show (projectTypedWitness statement packed).authorization.mode = .approvalStep from mode]
  by_cases first : input = 0
  · rw [if_pos first] at result ⊢
    exact result
  · rw [if_neg first] at result ⊢
    rw [project_typed_input_at statement packed default bound]
    simpa only [projectInput, active, Nat.one_ne_zero, if_false, exactV8SemanticPrimitives,
      prfWords, wordAt] using result

theorem admitted_final_input_effective_prf {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input = 1) :
    packedWord packed (rawIndex (95 + input)) = effectiveInputAuthorizationPrf
      exactV8SemanticPrimitives (projectTypedWitness statement packed) input := by
  have result := accepted_final_input_scalar domain.2.2 mode ⟨input, bound⟩
    ((admitted_public_input_flag domain bound).trans active)
  rw [← authorization_raw_word_eq_packed]
  unfold effectiveInputAuthorizationPrf
  dsimp only
  rw [show (projectTypedWitness statement packed).authorization.mode = .finalThresholdSpend from mode]
  exact result

theorem accepted_approval_input_key {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    (input : Fin 2) (active : publicWords.getD input.val 0 = 1) :
    (List.range 4).map (fun limb => authorizationRawWord packed (97 + 4 * input.val + limb)) =
      if input.val = 0 then (exactV8AccumulatorDigest (projectAccumulator packed 98)).take 4
      else ((exactV8TransactionPrf (prfWords packed)).drop 1).take 4 := by
  by_cases first : input.val = 0
  · rw [if_pos first]
    have key := accepted_authorization_digest_exact_key accepted ⟨0, by decide⟩
    change (List.range 4).map (fun limb => authorizationRawWord packed (110 + limb)) =
      (exactV8AccumulatorDigest (projectAccumulator packed 98)).take 4 at key
    rw [← key]
    apply List.map_congr_left
    intro limb member
    have bound := List.mem_range.mp member
    have source := accepted_active_approval_input_authorization_word accepted mode input
      ⟨1 + limb, by omega⟩ active
    have nonzero : 1 + limb ≠ 0 := by omega
    have outputRow : 96 + 4 * input.val + (1 + limb) = 97 + 4 * input.val + limb := by omega
    have keyRow : 109 + (1 + limb) = 110 + limb := by omega
    rw [inputAuthOutRow, if_neg nonzero, outputRow, inputAuthApprovalRow,
      if_pos first, if_neg nonzero, keyRow] at source
    exact source
  · rw [if_neg first, ← accepted_legacy_key_eq_exact_prf accepted]
    apply List.map_congr_left
    intro limb member
    have bound := List.mem_range.mp member
    have source := accepted_active_approval_input_authorization_word accepted mode input
      ⟨1 + limb, by omega⟩ active
    have nonzero : 1 + limb ≠ 0 := by omega
    have outputRow : 96 + 4 * input.val + (1 + limb) = 97 + 4 * input.val + limb := by omega
    have legacyRow : 105 + (1 + limb) = 106 + limb := by omega
    rw [inputAuthOutRow, if_neg nonzero, outputRow, inputAuthApprovalRow,
      if_neg first, legacyRow] at source
    exact source

theorem accepted_final_input_key {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend)
    (input : Fin 2) (active : publicWords.getD input.val 0 = 1) :
    (List.range 4).map (fun limb => authorizationRawWord packed (97 + 4 * input.val + limb)) =
      if input.val = 0 then (exactV8ValueLockDigest (projectAccumulator packed 98)).take 4
      else (exactV8AccumulatorDigest (projectAccumulator packed 98)).take 4 := by
  by_cases first : input.val = 0
  · rw [if_pos first]
    have key := accepted_authorization_digest_exact_key accepted ⟨2, by decide⟩
    change (List.range 4).map (fun limb => authorizationRawWord packed (124 + limb)) =
      (exactV8ValueLockDigest (projectAccumulator packed 98)).take 4 at key
    rw [← key]
    apply List.map_congr_left
    intro limb member
    have bound := List.mem_range.mp member
    have source := accepted_active_final_input_authorization_word accepted mode input
      ⟨1 + limb, by omega⟩ active
    have nonzero : 1 + limb ≠ 0 := by omega
    have outputRow : 96 + 4 * input.val + (1 + limb) = 97 + 4 * input.val + limb := by omega
    have keyRow : 123 + (1 + limb) = 124 + limb := by omega
    rw [inputAuthOutRow, if_neg nonzero, outputRow, inputAuthFinalRow,
      if_pos first, if_neg nonzero, keyRow] at source
    exact source
  · rw [if_neg first]
    have key := accepted_authorization_digest_exact_key accepted ⟨0, by decide⟩
    change (List.range 4).map (fun limb => authorizationRawWord packed (110 + limb)) =
      (exactV8AccumulatorDigest (projectAccumulator packed 98)).take 4 at key
    rw [← key]
    apply List.map_congr_left
    intro limb member
    have bound := List.mem_range.mp member
    have source := accepted_active_final_input_authorization_word accepted mode input
      ⟨1 + limb, by omega⟩ active
    have nonzero : 1 + limb ≠ 0 := by omega
    have outputRow : 96 + 4 * input.val + (1 + limb) = 97 + 4 * input.val + limb := by omega
    have keyRow : 109 + (1 + limb) = 110 + limb := by omega
    rw [inputAuthOutRow, if_neg nonzero, outputRow, inputAuthFinalRow,
      if_neg first, if_neg nonzero, keyRow] at source
    exact source

theorem admitted_approval_input_key {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input = 1) :
    ((projectTypedWitness statement packed).inputs.getD input default).note.authorizationKey =
      if input = 0 then (exactV8AccumulatorDigest (projectAuthorization packed).current).take 4
      else ((exactV8TransactionPrf (prfWords packed)).drop 1).take 4 := by
  rw [accepted_typed_input_authorization_source domain.2.2 statement ⟨input, bound⟩]
  simp only [← authorization_raw_word_eq_packed]
  exact accepted_approval_input_key domain.2.2 mode ⟨input, bound⟩
    ((admitted_public_input_flag domain bound).trans active)

theorem admitted_final_input_key {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .finalThresholdSpend)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input = 1) :
    ((projectTypedWitness statement packed).inputs.getD input default).note.authorizationKey =
      if input = 0 then (exactV8ValueLockDigest (projectAuthorization packed).current).take 4
      else (exactV8AccumulatorDigest (projectAuthorization packed).current).take 4 := by
  rw [accepted_typed_input_authorization_source domain.2.2 statement ⟨input, bound⟩]
  simp only [← authorization_raw_word_eq_packed]
  exact accepted_final_input_key domain.2.2 mode ⟨input, bound⟩
    ((admitted_public_input_flag domain bound).trans active)

def approvalOutputKeyExpressions (limb : Nat) : List (Nat × FieldExpression) :=
  [(217, .witnessRow 93), (200 + limb, .witnessRow (76 + limb)),
    (241 + limb, .witnessRow (117 + limb)),
    (1423 + 2 * limb, .sub (200 + limb) (241 + limb)),
    (1424 + 2 * limb, .mul 217 (1423 + 2 * limb))]

theorem approval_output_key_source (limb : Fin 4) :
    (approvalOutputKeyExpressions limb.val).all (fun entry =>
      exactNonlinearExpressions[entry.1]? == some entry.2) = true := by
  have checked : ∀ limb : Fin 4,
      (approvalOutputKeyExpressions limb.val).all (fun entry =>
        exactNonlinearExpressions[entry.1]? == some entry.2) = true := by decide
  exact checked limb

theorem approval_output_key_root (limb : Fin 4) :
    1424 + 2 * limb.val ∈ exactNonlinearRoots := by
  have checked : ∀ limb : Fin 4, 1424 + 2 * limb.val ∈ exactNonlinearRoots := by decide
  exact checked limb

/-- The four output-zero authorization words are gated by the actual approval
mode root, not by an assumed canonical next accumulator. -/
theorem accepted_approval_output_key_word {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) (limb : Fin 4) :
    authorizationRawWord packed (76 + limb.val) = authorizationRawWord packed (117 + limb.val) := by
  obtain ⟨values, equations, rootZero⟩ := accepted_nonlinear_field_trace accepted
    (lane := 0) (root := 1424 + 2 * limb.val) (by decide) (approval_output_key_root limb)
  have source (index : Nat) (expression : FieldExpression)
      (member : (index, expression) ∈ approvalOutputKeyExpressions limb.val) :
      exactNonlinearExpressions[index]? = some expression :=
    eq_of_beq (List.all_eq_true.mp (approval_output_key_source limb) (index, expression) member)
  have gate := equations 217 (.witnessRow 93) (source _ _ (by simp [approvalOutputKeyExpressions]))
  have left := equations (200 + limb.val) (.witnessRow (76 + limb.val))
    (source _ _ (by simp [approvalOutputKeyExpressions]))
  have right := equations (241 + limb.val) (.witnessRow (117 + limb.val))
    (source _ _ (by simp [approvalOutputKeyExpressions]))
  have difference := equations (1423 + 2 * limb.val) (.sub (200 + limb.val) (241 + limb.val))
    (source _ _ (by simp [approvalOutputKeyExpressions]))
  have root := equations (1424 + 2 * limb.val) (.mul 217 (1423 + 2 * limb.val))
    (source _ _ (by simp [approvalOutputKeyExpressions]))
  simp only [expressionField] at gate left right difference root
  rw [authorization_lane_zero_word packed (by decide : 93 < 686), show 93 = 92 + 1 by decide,
    input_authorization_raw_mode_word, accepted_approval_mode_word accepted mode, Nat.cast_one] at gate
  rw [authorization_lane_zero_word packed (by have := limb.isLt; omega : 76 + limb.val < 686)] at left
  rw [authorization_lane_zero_word packed (by have := limb.isLt; omega : 117 + limb.val < 686)] at right
  rw [rootZero, gate, one_mul, difference, left, right] at root
  exact canonical_nat_cast_injective (packed_word_canonical accepted.2.1 _)
    (packed_word_canonical accepted.2.1 _) (sub_eq_zero.mp root.symm)

theorem admitted_approval_output_zero_key {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    ((projectTypedWitness statement packed).outputs.getD 0 default).note.authorizationKey =
      (exactV8AccumulatorDigest (projectAuthorization packed).next).take 4 := by
  rw [accepted_typed_output_authorization_source domain.2.2 statement ⟨0, by decide⟩]
  simp only [← authorization_raw_word_eq_packed]
  have digest := accepted_authorization_digest_exact_key domain.2.2 ⟨1, by decide⟩
  simp only [authorizationExactDigest, Nat.one_ne_zero, if_false, if_true,
    Nat.mul_one, Nat.reduceAdd] at digest
  simp only [projectAuthorization, mode, if_true]
  rw [← digest]
  apply List.map_congr_left
  intro limb member
  exact accepted_approval_output_key_word domain.2.2 mode ⟨limb, List.mem_range.mp member⟩

theorem accepted_legacy_tag_eq_exact_prf {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed) :
    authorizationRawLegacyTag packed = (exactV8TransactionPrf (prfWords packed)).take signerTagWords := by
  rw [← accepted_prf_digest_eq_exact accepted]
  apply List.ext_getElem
  · simp [authorizationRawLegacyTag, HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes.packedFinalState,
      digestWords, signerTagWords]
  · intro limb leftBound rightBound
    have bound : limb < 5 := by simpa [authorizationRawLegacyTag] using leftBound
    simp only [authorizationRawLegacyTag, List.getElem_map, List.getElem_range,
      List.getElem_take, HegemonCrypto.SmallWood.V8Smz9SemanticEndpointNotes.packedFinalState]
    exact accepted_legacy_word_eq_hash_final accepted ⟨limb, bound⟩

theorem admitted_approval_signer_bound {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    (mode : projectAuthorizationMode packed = .approvalStep) :
    ApprovalSignerBound
      (exactV8TransactionPrf (selectedTransactionSpendKey statement (projectTypedWitness statement packed)))
      (projectAuthorization packed) := by
  have activity := (admitted_approval_activity domain mode).1
  have active : flagAt statement.inputFlags 0 = 1 := by simp [activity, flagAt]
  rw [selected_project_transaction_spend_key statement packed (by decide : 0 < 2) active]
  intro slot bound changed
  have source := accepted_approval_raw_signer_bound domain.2.2 mode slot bound changed
  rw [accepted_legacy_tag_eq_exact_prf domain.2.2] at source
  simpa only [List.take_take, Nat.min_self] using source


end HegemonCrypto.SmallWood.V8Smz9NonSingleAuthorizationLinks
