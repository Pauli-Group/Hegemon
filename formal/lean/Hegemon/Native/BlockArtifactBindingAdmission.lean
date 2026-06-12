namespace Hegemon
namespace Native
namespace BlockArtifactBindingAdmission

inductive TxLeafActionBindingReject where
  | nullifiersMismatch
  | commitmentsMismatch
  | ciphertextHashesMismatch
  | inputCountMismatch
  | outputCountMismatch
  | versionMismatch
  | feeMismatch
  | stablecoinPayloadMismatch
  | balanceTagMismatch
  | receiptStatementHashMismatch
  | publicInputsDigestMismatch
  | proofDigestMismatch
  | proofBackendMismatch
  | ciphertextPayloadHashMismatch
deriving DecidableEq, Repr

structure TxLeafActionBindingInput where
  nullifiersMatch : Bool
  commitmentsMatch : Bool
  ciphertextHashesMatch : Bool
  inputCountMatches : Bool
  outputCountMatches : Bool
  versionMatches : Bool
  feeMatches : Bool
  stablecoinPayloadMatches : Bool
  balanceTagMatches : Bool
  receiptStatementHashMatches : Bool
  publicInputsDigestMatches : Bool
  proofDigestMatches : Bool
  proofBackendMatches : Bool
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
  else if !input.inputCountMatches then
    Except.error TxLeafActionBindingReject.inputCountMismatch
  else if !input.outputCountMatches then
    Except.error TxLeafActionBindingReject.outputCountMismatch
  else if !input.versionMatches then
    Except.error TxLeafActionBindingReject.versionMismatch
  else if !input.feeMatches then
    Except.error TxLeafActionBindingReject.feeMismatch
  else if !input.stablecoinPayloadMatches then
    Except.error TxLeafActionBindingReject.stablecoinPayloadMismatch
  else if !input.balanceTagMatches then
    Except.error TxLeafActionBindingReject.balanceTagMismatch
  else if !input.receiptStatementHashMatches then
    Except.error TxLeafActionBindingReject.receiptStatementHashMismatch
  else if !input.publicInputsDigestMatches then
    Except.error TxLeafActionBindingReject.publicInputsDigestMismatch
  else if !input.proofDigestMatches then
    Except.error TxLeafActionBindingReject.proofDigestMismatch
  else if !input.proofBackendMatches then
    Except.error TxLeafActionBindingReject.proofBackendMismatch
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
    && input.inputCountMatches
    && input.outputCountMatches
    && input.versionMatches
    && input.feeMatches
    && input.stablecoinPayloadMatches
    && input.balanceTagMatches
    && input.receiptStatementHashMatches
    && input.publicInputsDigestMatches
    && input.proofDigestMatches
    && input.proofBackendMatches
    && input.ciphertextPayloadHashesMatch

theorem tx_leaf_action_accepts_iff_preconditions
    (input : TxLeafActionBindingInput) :
    txLeafActionBindingAccepts input =
      txLeafActionBindingPreconditions input := by
  unfold txLeafActionBindingAccepts
    txLeafActionBindingPreconditions
    evaluateTxLeafActionBinding
  by_cases h0 : input.nullifiersMatch
  · simp [h0]
    by_cases h1 : input.commitmentsMatch
    · simp [h1]
      by_cases h2 : input.ciphertextHashesMatch
      · simp [h2]
        by_cases h3 : input.inputCountMatches
        · simp [h3]
          by_cases h4 : input.outputCountMatches
          · simp [h4]
            by_cases h5 : input.versionMatches
            · simp [h5]
              by_cases h6 : input.feeMatches
              · simp [h6]
                by_cases h7 : input.stablecoinPayloadMatches
                · simp [h7]
                  by_cases h8 : input.balanceTagMatches
                  · simp [h8]
                    by_cases h9 : input.receiptStatementHashMatches
                    · simp [h9]
                      by_cases h10 : input.publicInputsDigestMatches
                      · simp [h10]
                        by_cases h11 : input.proofDigestMatches
                        · simp [h11]
                          by_cases h12 : input.proofBackendMatches
                          · simp [h12]
                            by_cases h13 : input.ciphertextPayloadHashesMatch
                            · simp [h13]
                            · simp [h13]
                          · simp [h12]
                        · simp [h11]
                      · simp [h10]
                    · simp [h9]
                  · simp [h8]
                · simp [h7]
              · simp [h6]
            · simp [h5]
          · simp [h4]
        · simp [h3]
      · simp [h2]
    · simp [h1]
  · simp [h0]

def validTxLeafActionBinding : TxLeafActionBindingInput :=
  {
    nullifiersMatch := true,
    commitmentsMatch := true,
    ciphertextHashesMatch := true,
    inputCountMatches := true,
    outputCountMatches := true,
    versionMatches := true,
    feeMatches := true,
    stablecoinPayloadMatches := true,
    balanceTagMatches := true,
    receiptStatementHashMatches := true,
    publicInputsDigestMatches := true,
    proofDigestMatches := true,
    proofBackendMatches := true,
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

theorem tx_leaf_input_count_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with inputCountMatches := false } =
      Except.error TxLeafActionBindingReject.inputCountMismatch := by
  rfl

theorem tx_leaf_output_count_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with outputCountMatches := false } =
      Except.error TxLeafActionBindingReject.outputCountMismatch := by
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

theorem tx_leaf_fee_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with feeMatches := false } =
      Except.error TxLeafActionBindingReject.feeMismatch := by
  rfl

theorem tx_leaf_stablecoin_payload_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with stablecoinPayloadMatches := false } =
      Except.error TxLeafActionBindingReject.stablecoinPayloadMismatch := by
  rfl

theorem tx_leaf_balance_tag_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with balanceTagMatches := false } =
      Except.error TxLeafActionBindingReject.balanceTagMismatch := by
  rfl

theorem tx_leaf_receipt_statement_hash_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with receiptStatementHashMatches := false } =
      Except.error TxLeafActionBindingReject.receiptStatementHashMismatch := by
  rfl

theorem tx_leaf_public_inputs_digest_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with publicInputsDigestMatches := false } =
      Except.error TxLeafActionBindingReject.publicInputsDigestMismatch := by
  rfl

theorem tx_leaf_proof_digest_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with proofDigestMatches := false } =
      Except.error TxLeafActionBindingReject.proofDigestMismatch := by
  rfl

theorem tx_leaf_proof_backend_mismatch_rejects :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with proofBackendMatches := false } =
      Except.error TxLeafActionBindingReject.proofBackendMismatch := by
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

theorem tx_leaf_ciphertext_hashes_precede_counts :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          ciphertextHashesMatch := false,
          inputCountMatches := false,
          outputCountMatches := false } =
      Except.error TxLeafActionBindingReject.ciphertextHashesMismatch := by
  rfl

theorem tx_leaf_input_count_precedes_output_count :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          inputCountMatches := false,
          outputCountMatches := false,
          versionMatches := false } =
      Except.error TxLeafActionBindingReject.inputCountMismatch := by
  rfl

theorem tx_leaf_output_count_precedes_version :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          outputCountMatches := false,
          versionMatches := false } =
      Except.error TxLeafActionBindingReject.outputCountMismatch := by
  rfl

theorem tx_leaf_version_precedes_payload_hashes :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          versionMatches := false,
          feeMatches := false,
          stablecoinPayloadMatches := false,
          ciphertextPayloadHashesMatch := false } =
      Except.error TxLeafActionBindingReject.versionMismatch := by
  rfl

theorem tx_leaf_fee_precedes_stablecoin_payload :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          feeMatches := false,
          stablecoinPayloadMatches := false,
          balanceTagMatches := false,
          ciphertextPayloadHashesMatch := false } =
      Except.error TxLeafActionBindingReject.feeMismatch := by
  rfl

theorem tx_leaf_stablecoin_payload_precedes_balance_tag :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          stablecoinPayloadMatches := false,
          balanceTagMatches := false,
          receiptStatementHashMatches := false,
          publicInputsDigestMatches := false,
          proofDigestMatches := false,
          proofBackendMatches := false,
          ciphertextPayloadHashesMatch := false } =
      Except.error TxLeafActionBindingReject.stablecoinPayloadMismatch := by
  rfl

theorem tx_leaf_balance_tag_precedes_receipt :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          balanceTagMatches := false,
          receiptStatementHashMatches := false,
          publicInputsDigestMatches := false,
          proofDigestMatches := false,
          proofBackendMatches := false } =
      Except.error TxLeafActionBindingReject.balanceTagMismatch := by
  rfl

theorem tx_leaf_receipt_statement_precedes_public_inputs_digest :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          receiptStatementHashMatches := false,
          publicInputsDigestMatches := false,
          proofDigestMatches := false } =
      Except.error TxLeafActionBindingReject.receiptStatementHashMismatch := by
  rfl

theorem tx_leaf_public_inputs_digest_precedes_proof_digest :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          publicInputsDigestMatches := false,
          proofDigestMatches := false,
          proofBackendMatches := false } =
      Except.error TxLeafActionBindingReject.publicInputsDigestMismatch := by
  rfl

theorem tx_leaf_proof_digest_precedes_backend :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          proofDigestMatches := false,
          proofBackendMatches := false,
          ciphertextPayloadHashesMatch := false } =
      Except.error TxLeafActionBindingReject.proofDigestMismatch := by
  rfl

theorem tx_leaf_proof_backend_precedes_payload_hashes :
    evaluateTxLeafActionBinding
        { validTxLeafActionBinding with
          proofBackendMatches := false,
          ciphertextPayloadHashesMatch := false } =
      Except.error TxLeafActionBindingReject.proofBackendMismatch := by
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
