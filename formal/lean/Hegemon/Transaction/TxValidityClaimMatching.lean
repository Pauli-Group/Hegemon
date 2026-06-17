namespace Hegemon
namespace Transaction
namespace TxValidityClaimMatching

inductive ClaimMatchReject where
  | countMismatch
  | receiptStatementHashMismatch
  | receiptProofDigestMismatch
  | receiptPublicInputsDigestMismatch
  | receiptVerifierProfileMismatch
  | bindingStatementHashMismatch
  | bindingAnchorRootMismatch
  | bindingFeeMismatch
  | bindingCircuitVersionMismatch
deriving DecidableEq, Repr

structure ClaimMatchInput where
  countMatches : Bool
  receiptStatementHashMatches : Bool
  receiptProofDigestMatches : Bool
  receiptPublicInputsDigestMatches : Bool
  receiptVerifierProfileMatches : Bool
  bindingStatementHashMatches : Bool
  bindingAnchorRootMatches : Bool
  bindingFeeMatches : Bool
  bindingCircuitVersionMatches : Bool
deriving DecidableEq, Repr

def claimMatchPreconditions (input : ClaimMatchInput) : Bool :=
  input.countMatches
    && input.receiptStatementHashMatches
    && input.receiptProofDigestMatches
    && input.receiptPublicInputsDigestMatches
    && input.receiptVerifierProfileMatches
    && input.bindingStatementHashMatches
    && input.bindingAnchorRootMatches
    && input.bindingFeeMatches
    && input.bindingCircuitVersionMatches

def firstClaimMatchRejection (input : ClaimMatchInput) : ClaimMatchReject :=
  if !input.countMatches then
    ClaimMatchReject.countMismatch
  else if !input.receiptStatementHashMatches then
    ClaimMatchReject.receiptStatementHashMismatch
  else if !input.receiptProofDigestMatches then
    ClaimMatchReject.receiptProofDigestMismatch
  else if !input.receiptPublicInputsDigestMatches then
    ClaimMatchReject.receiptPublicInputsDigestMismatch
  else if !input.receiptVerifierProfileMatches then
    ClaimMatchReject.receiptVerifierProfileMismatch
  else if !input.bindingStatementHashMatches then
    ClaimMatchReject.bindingStatementHashMismatch
  else if !input.bindingAnchorRootMatches then
    ClaimMatchReject.bindingAnchorRootMismatch
  else if !input.bindingFeeMatches then
    ClaimMatchReject.bindingFeeMismatch
  else if !input.bindingCircuitVersionMatches then
    ClaimMatchReject.bindingCircuitVersionMismatch
  else
    ClaimMatchReject.bindingCircuitVersionMismatch

def evaluateClaimMatchRejection
    (input : ClaimMatchInput) : Option ClaimMatchReject :=
  if claimMatchPreconditions input then
    none
  else
    some (firstClaimMatchRejection input)

def claimMatchAccepts (input : ClaimMatchInput) : Bool :=
  evaluateClaimMatchRejection input = none

def acceptedClaimMatchSurface (input : ClaimMatchInput) : Prop :=
  input.countMatches = true
    ∧ input.receiptStatementHashMatches = true
    ∧ input.receiptProofDigestMatches = true
    ∧ input.receiptPublicInputsDigestMatches = true
    ∧ input.receiptVerifierProfileMatches = true
    ∧ input.bindingStatementHashMatches = true
    ∧ input.bindingAnchorRootMatches = true
    ∧ input.bindingFeeMatches = true
    ∧ input.bindingCircuitVersionMatches = true

theorem accepts_iff_claim_match_preconditions {input : ClaimMatchInput} :
    claimMatchAccepts input = true ↔ claimMatchPreconditions input = true := by
  by_cases h : claimMatchPreconditions input <;>
    simp [claimMatchAccepts, evaluateClaimMatchRejection, h]

theorem claimMatchAccepts_implies_exact_surface {input : ClaimMatchInput}
    (accepted : claimMatchAccepts input = true) :
    acceptedClaimMatchSurface input := by
  have preconditions :=
    (accepts_iff_claim_match_preconditions (input := input)).mp accepted
  simp [claimMatchPreconditions] at preconditions
  rcases preconditions with ⟨preconditions, bindingCircuitVersionMatches⟩
  rcases preconditions with ⟨preconditions, bindingFeeMatches⟩
  rcases preconditions with ⟨preconditions, bindingAnchorRootMatches⟩
  rcases preconditions with ⟨preconditions, bindingStatementHashMatches⟩
  rcases preconditions with ⟨preconditions, receiptVerifierProfileMatches⟩
  rcases preconditions with ⟨preconditions, receiptPublicInputsDigestMatches⟩
  rcases preconditions with ⟨preconditions, receiptProofDigestMatches⟩
  rcases preconditions with ⟨countMatches, receiptStatementHashMatches⟩
  exact
    ⟨countMatches, receiptStatementHashMatches, receiptProofDigestMatches,
      receiptPublicInputsDigestMatches, receiptVerifierProfileMatches,
      bindingStatementHashMatches, bindingAnchorRootMatches, bindingFeeMatches,
      bindingCircuitVersionMatches⟩

theorem accepted_tx_validity_claim_fields_match_verified_artifact
    {input : ClaimMatchInput}
    (accepted : claimMatchAccepts input = true) :
    acceptedClaimMatchSurface input :=
  claimMatchAccepts_implies_exact_surface accepted

def validClaimMatch : ClaimMatchInput :=
  { countMatches := true
    receiptStatementHashMatches := true
    receiptProofDigestMatches := true
    receiptPublicInputsDigestMatches := true
    receiptVerifierProfileMatches := true
    bindingStatementHashMatches := true
    bindingAnchorRootMatches := true
    bindingFeeMatches := true
    bindingCircuitVersionMatches := true }

theorem valid_claim_match_accepts :
    evaluateClaimMatchRejection validClaimMatch = none := by
  decide

theorem count_mismatch_rejects :
    evaluateClaimMatchRejection { validClaimMatch with countMatches := false } =
      some ClaimMatchReject.countMismatch := by
  decide

theorem receipt_statement_hash_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with receiptStatementHashMatches := false } =
      some ClaimMatchReject.receiptStatementHashMismatch := by
  decide

theorem receipt_proof_digest_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with receiptProofDigestMatches := false } =
      some ClaimMatchReject.receiptProofDigestMismatch := by
  decide

theorem receipt_public_inputs_digest_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with receiptPublicInputsDigestMatches := false } =
      some ClaimMatchReject.receiptPublicInputsDigestMismatch := by
  decide

theorem receipt_verifier_profile_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with receiptVerifierProfileMatches := false } =
      some ClaimMatchReject.receiptVerifierProfileMismatch := by
  decide

theorem binding_statement_hash_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with bindingStatementHashMatches := false } =
      some ClaimMatchReject.bindingStatementHashMismatch := by
  decide

theorem binding_anchor_root_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with bindingAnchorRootMatches := false } =
      some ClaimMatchReject.bindingAnchorRootMismatch := by
  decide

theorem binding_fee_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with bindingFeeMatches := false } =
      some ClaimMatchReject.bindingFeeMismatch := by
  decide

theorem binding_circuit_version_mismatch_rejects :
    evaluateClaimMatchRejection
      { validClaimMatch with bindingCircuitVersionMatches := false } =
      some ClaimMatchReject.bindingCircuitVersionMismatch := by
  decide

theorem receipt_statement_precedes_later_mismatch :
    evaluateClaimMatchRejection
      { validClaimMatch with
        receiptStatementHashMatches := false,
        bindingAnchorRootMatches := false } =
      some ClaimMatchReject.receiptStatementHashMismatch := by
  decide

end TxValidityClaimMatching
end Transaction
end Hegemon
