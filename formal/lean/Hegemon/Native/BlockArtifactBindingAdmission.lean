namespace Hegemon
namespace Native
namespace BlockArtifactBindingAdmission

inductive TxLeafActionBindingReject where
  | nullifiersMismatch
  | commitmentsMismatch
  | ciphertextHashesMismatch
  | versionMismatch
  | ciphertextPayloadHashMismatch
deriving DecidableEq, Repr

structure TxLeafActionBindingInput where
  nullifiersMatch : Bool
  commitmentsMatch : Bool
  ciphertextHashesMatch : Bool
  versionMatches : Bool
  ciphertextPayloadHashesMatch : Bool
deriving DecidableEq, Repr

def evaluateTxLeafActionBinding
    (input : TxLeafActionBindingInput) :
    Except TxLeafActionBindingReject Unit :=
  if !input.nullifiersMatch then
    Except.error TxLeafActionBindingReject.nullifiersMismatch
  else if !input.commitmentsMatch then
    Except.error TxLeafActionBindingReject.commitmentsMismatch
  else if !input.ciphertextHashesMatch then
    Except.error TxLeafActionBindingReject.ciphertextHashesMismatch
  else if !input.versionMatches then
    Except.error TxLeafActionBindingReject.versionMismatch
  else if !input.ciphertextPayloadHashesMatch then
    Except.error TxLeafActionBindingReject.ciphertextPayloadHashMismatch
  else
    Except.ok ()

def txLeafActionBindingAccepts
    (input : TxLeafActionBindingInput) : Bool :=
  match evaluateTxLeafActionBinding input with
  | Except.ok _ => true
  | Except.error _ => false

def txLeafActionBindingRejection
    (input : TxLeafActionBindingInput) :
    Option TxLeafActionBindingReject :=
  match evaluateTxLeafActionBinding input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def txLeafActionBindingPreconditions
    (input : TxLeafActionBindingInput) : Bool :=
  input.nullifiersMatch
    && input.commitmentsMatch
    && input.ciphertextHashesMatch
    && input.versionMatches
    && input.ciphertextPayloadHashesMatch

theorem tx_leaf_action_accepts_iff_preconditions
    (input : TxLeafActionBindingInput) :
    txLeafActionBindingAccepts input =
      txLeafActionBindingPreconditions input := by
  cases input with
  | mk nullifiersMatch commitmentsMatch ciphertextHashesMatch
      versionMatches ciphertextPayloadHashesMatch =>
      unfold txLeafActionBindingAccepts
        txLeafActionBindingPreconditions
        evaluateTxLeafActionBinding
      cases nullifiersMatch <;> cases commitmentsMatch <;>
        cases ciphertextHashesMatch <;> cases versionMatches <;>
        cases ciphertextPayloadHashesMatch <;> simp

def validTxLeafActionBinding : TxLeafActionBindingInput :=
  {
    nullifiersMatch := true,
    commitmentsMatch := true,
    ciphertextHashesMatch := true,
    versionMatches := true,
    ciphertextPayloadHashesMatch := true
  }

theorem valid_tx_leaf_action_binding_accepts :
    evaluateTxLeafActionBinding validTxLeafActionBinding = Except.ok () := by
  rfl

theorem tx_leaf_nullifiers_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with nullifiersMatch := false } =
      Except.error TxLeafActionBindingReject.nullifiersMismatch := by
  rfl

theorem tx_leaf_commitments_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with commitmentsMatch := false } =
      Except.error TxLeafActionBindingReject.commitmentsMismatch := by
  rfl

theorem tx_leaf_ciphertext_hashes_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with ciphertextHashesMatch := false } =
      Except.error TxLeafActionBindingReject.ciphertextHashesMismatch := by
  rfl

theorem tx_leaf_version_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with versionMatches := false } =
      Except.error TxLeafActionBindingReject.versionMismatch := by
  rfl

theorem tx_ciphertext_payload_hash_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          ciphertextPayloadHashesMatch := false } =
      Except.error TxLeafActionBindingReject.ciphertextPayloadHashMismatch := by
  rfl

theorem tx_leaf_nullifiers_precede_commitments :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          nullifiersMatch := false,
          commitmentsMatch := false } =
      Except.error TxLeafActionBindingReject.nullifiersMismatch := by
  rfl

theorem tx_leaf_commitments_precede_ciphertext_hashes :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          commitmentsMatch := false,
          ciphertextHashesMatch := false } =
      Except.error TxLeafActionBindingReject.commitmentsMismatch := by
  rfl

theorem tx_leaf_version_precedes_payload_hashes :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          versionMatches := false,
          ciphertextPayloadHashesMatch := false } =
      Except.error TxLeafActionBindingReject.versionMismatch := by
  rfl

inductive CandidateArtifactBindingReject where
  | daRootMismatch
  | txStatementCommitmentMismatch
  | recursiveStateRootMismatch
deriving DecidableEq, Repr

structure CandidateArtifactBindingInput where
  daRootMatches : Bool
  txStatementsCommitmentMatches : Bool
  recursiveStateRootMatches : Bool
deriving DecidableEq, Repr

def evaluateCandidateArtifactBinding
    (input : CandidateArtifactBindingInput) :
    Except CandidateArtifactBindingReject Unit :=
  if !input.daRootMatches then
    Except.error CandidateArtifactBindingReject.daRootMismatch
  else if !input.txStatementsCommitmentMatches then
    Except.error CandidateArtifactBindingReject.txStatementCommitmentMismatch
  else if !input.recursiveStateRootMatches then
    Except.error CandidateArtifactBindingReject.recursiveStateRootMismatch
  else
    Except.ok ()

def candidateArtifactBindingAccepts
    (input : CandidateArtifactBindingInput) : Bool :=
  match evaluateCandidateArtifactBinding input with
  | Except.ok _ => true
  | Except.error _ => false

def candidateArtifactBindingRejection
    (input : CandidateArtifactBindingInput) :
    Option CandidateArtifactBindingReject :=
  match evaluateCandidateArtifactBinding input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def candidateArtifactBindingPreconditions
    (input : CandidateArtifactBindingInput) : Bool :=
  input.daRootMatches
    && input.txStatementsCommitmentMatches
    && input.recursiveStateRootMatches

theorem candidate_artifact_binding_accepts_iff_preconditions
    (input : CandidateArtifactBindingInput) :
    candidateArtifactBindingAccepts input =
      candidateArtifactBindingPreconditions input := by
  cases input with
  | mk daRootMatches txStatementsCommitmentMatches recursiveStateRootMatches =>
      unfold candidateArtifactBindingAccepts
        candidateArtifactBindingPreconditions
        evaluateCandidateArtifactBinding
      cases daRootMatches <;> cases txStatementsCommitmentMatches <;>
        cases recursiveStateRootMatches <;> simp

def validCandidateArtifactBinding : CandidateArtifactBindingInput :=
  {
    daRootMatches := true,
    txStatementsCommitmentMatches := true,
    recursiveStateRootMatches := true
  }

theorem valid_candidate_artifact_binding_accepts :
    evaluateCandidateArtifactBinding validCandidateArtifactBinding = Except.ok () := by
  rfl

theorem candidate_da_root_mismatch_rejects :
    evaluateCandidateArtifactBinding
        { validCandidateArtifactBinding with daRootMatches := false } =
      Except.error CandidateArtifactBindingReject.daRootMismatch := by
  rfl

theorem candidate_statement_commitment_mismatch_rejects :
    evaluateCandidateArtifactBinding
        { validCandidateArtifactBinding with
          txStatementsCommitmentMatches := false } =
      Except.error CandidateArtifactBindingReject.txStatementCommitmentMismatch := by
  rfl

theorem candidate_recursive_state_root_mismatch_rejects :
    evaluateCandidateArtifactBinding
        { validCandidateArtifactBinding with
          recursiveStateRootMatches := false } =
      Except.error CandidateArtifactBindingReject.recursiveStateRootMismatch := by
  rfl

theorem candidate_da_root_precedes_statement_commitment :
    evaluateCandidateArtifactBinding
        { validCandidateArtifactBinding with
          daRootMatches := false,
          txStatementsCommitmentMatches := false } =
      Except.error CandidateArtifactBindingReject.daRootMismatch := by
  rfl

theorem candidate_statement_precedes_state_root :
    evaluateCandidateArtifactBinding
        { validCandidateArtifactBinding with
          txStatementsCommitmentMatches := false,
          recursiveStateRootMatches := false } =
      Except.error CandidateArtifactBindingReject.txStatementCommitmentMismatch := by
  rfl

end BlockArtifactBindingAdmission
end Native
end Hegemon
