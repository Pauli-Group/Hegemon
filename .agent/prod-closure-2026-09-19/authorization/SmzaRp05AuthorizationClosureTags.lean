import SmzaRp05AcceptedSingleKeySemanticIdentity
import SmzaRp05LocalCertificate

/-! Bind the seven scalar signer-tag rows used by selected membership to
the actual call-0 SingleKey digest. The seven finite CSR memberships below
are the source edge between the existing vector-digest and local full-tag
theorems; all facts concern one accepted packed witness. -/
namespace HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureTags

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement (hashFinalIndex)
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCertificate
open HegemonCrypto.SmallWood.SmzaRp05AcceptedSingleKeySemanticIdentity
open HegemonCrypto.SmallWood.SmzaRp05LiveAuthorizationIdentity
open HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder (packed_word_canonical)
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

def signerTagAttempt (limb : Fin 7) : CsrExecutableAttempt :=
  { globalIndex := 19126 + 4 * limb.val
    family := 41
    localIndex := 3 + 4 * limb.val
    emission := 0
    terms := [((99 + limb.val) * 64, 1), (28736 + 64 * limb.val, 3)]
    targetRoot := 0 }

theorem signerTagAttempt_member (limb : Fin 7) :
    signerTagAttempt limb ∈ program.csrAttempts := by
  fin_cases limb <;> decide

private theorem constant_trace_value {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] program.csrExpressions =
      some values) (node value : Nat)
    (found : program.csrExpressions[node]? = some (.constant value)) :
    (values.getD node 0 : Goldilocks) = (value : Goldilocks) := by
  have realizes : Realizes program.csrExpressions node (.constant value) :=
    Realizes.constant found
  have refined := fieldAt_refines_source
    ({ expressions := program.csrExpressions, roots := [] } : ExpressionProgram)
    publicWords [] values
    HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCanonical.csrCanonical
    evaluated node (List.getElem?_eq_some_iff.mp found).1
  rw [fieldAt_of_realizes realizes] at refined
  simpa [SourceTerm.eval] using refined.symm

/-- Every scalar signer-tag word is the actual call-0 digest word. -/
theorem accepted_scalar_tag_eq_call0 {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (limb : Fin 7) :
    packed.getD ((99 + limb.val) * 64) 0 =
      packed.getD (hashFinalIndex 0 limb.val) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have zero := constant_trace_value evaluated 0 0 (by decide)
  have one := constant_trace_value evaluated 1 1 (by decide)
  have minusOne := constant_trace_value evaluated 3 18446744069414584320 (by decide)
  have minusOneValue : (values.getD 3 0 : Goldilocks) = -1 := by
    rw [minusOne]
    decide
  have equation := accepted_csr_attempt_field_equality
    (attempts (signerTagAttempt limb) (signerTagAttempt_member limb))
  simp only [signerTagAttempt, csrFieldSum, List.map_cons, List.map_nil,
    List.sum_cons, List.sum_nil, zero, one, minusOneValue,
    neg_one_mul, add_zero] at equation
  have finalIndex : hashFinalIndex 0 limb.val = 28736 + 64 * limb.val := by
    simp [hashFinalIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.hashFinalRowOffset]
    omega
  rw [finalIndex]
  apply canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 ((99 + limb.val) * 64))
    (packed_word_canonical accepted.2.1 (28736 + 64 * limb.val))
  simp only [HegemonCrypto.SmallWood.V8Smz9SemanticDecoder.packedWord]
  linear_combination equation

theorem accepted_scalar_tag_eq_semantic_single_key_digest
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed) (limb : Fin 7) :
    packed.getD ((99 + limb.val) * 64) 0 =
      (LiveAuthorizationInput.digest
        (.singleKey (acceptedGlobalKey packed))).getD limb.val 0 := by
  exact (accepted_scalar_tag_eq_call0 accepted limb).trans
    ((accepted_legacy_digest_word accepted limb).symm.trans
      (accepted_legacy_words_eq_semantic_single_key_digest accepted limb))

private theorem lane_zero_row (packed : List Nat) (row : Nat)
    (bound : row < relationRowCount) :
    (packedWitnessLaneRows packed 0).getD row 0 =
      packed.getD (row * 64) 0 := by
  simp [packedWitnessLaneRows, List.getD_eq_getElem?_getD, bound,
    packingFactor]

/-- Selected Approval membership identifies all seven policy tag words
with the exact SingleKey sponge of the accepted global key. The mode and
selected-slot premises name the actual checked selector rows. -/
theorem accepted_selected_policy_tag_eq_semantic_single_key_digest
    {publicWords packed : List Nat}
    (accepted : program.AcceptsPacked publicWords packed)
    (approvalSelected : packed.getD (93 * 64) 0 = 1)
    (slot : Fin 6)
    (membershipSelected : packed.getD ((206 + slot.val) * 64) 0 = 1)
    (limb : Fin 7) :
    packed.getD ((164 + 7 * slot.val + limb.val) * 64) 0 =
      (LiveAuthorizationInput.digest
        (.singleKey (acceptedGlobalKey packed))).getD limb.val 0 := by
  have semantic := packed_program_implies_local_semantics
    HegemonCrypto.SmallWood.SmzaRp05LocalCertificate.certificate accepted 0
  have approval : ((packedWitnessLaneRows packed 0).getD approvalRow 0 : Goldilocks) = 1 := by
    rw [lane_zero_row packed approvalRow (by decide)]
    simpa [approvalRow] using congrArg (fun n : Nat => (n : Goldilocks)) approvalSelected
  have membership :
      ((packedWitnessLaneRows packed 0).getD (membershipRow slot) 0 : Goldilocks) = 1 := by
    rw [lane_zero_row packed (membershipRow slot) (by
      have bound := slot.isLt
      simp [membershipRow, relationRowCount]
      omega)]
    simpa [membershipRow] using
      congrArg (fun n : Nat => (n : Goldilocks)) membershipSelected
  have fullTag := congrFun
    (local_selected_full_tag_equality semantic approval slot membership) limb
  change ((packedWitnessLaneRows packed 0).getD (legacyTagRow limb) 0 : Goldilocks) =
    ((packedWitnessLaneRows packed 0).getD (policyTagRow slot limb) 0 : Goldilocks)
    at fullTag
  have legacyBound : legacyTagRow limb < relationRowCount := by
    have bound := limb.isLt
    simp [legacyTagRow, relationRowCount]
    omega
  have policyBound : policyTagRow slot limb < relationRowCount := by
    have slotBound := slot.isLt
    have limbBound := limb.isLt
    simp [policyTagRow, relationRowCount]
    omega
  rw [lane_zero_row packed (legacyTagRow limb) legacyBound,
    lane_zero_row packed (policyTagRow slot limb) policyBound] at fullTag
  have equalNat := canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (legacyTagRow limb * 64))
    (packed_word_canonical accepted.2.1 (policyTagRow slot limb * 64)) fullTag
  exact equalNat.symm.trans (accepted_scalar_tag_eq_semantic_single_key_digest
    accepted limb)

end HegemonCrypto.SmallWood.SmzaRp05AuthorizationClosureTags
