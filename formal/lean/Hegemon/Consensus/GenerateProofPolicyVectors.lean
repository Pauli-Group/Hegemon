import Hegemon.Consensus.ProofPolicy

open Hegemon.Consensus

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def verificationModeJson : VerificationMode -> String
  | VerificationMode.inlineRequired => "inline_required"
  | VerificationMode.selfContained => "self_contained"

def batchModeJson : BatchMode -> String
  | BatchMode.inlineTx => "inline_tx"
  | BatchMode.receiptRoot => "receipt_root"
  | BatchMode.recursiveBlock => "recursive_block"

def rejectionJson : Option ProofPolicyReject -> String
  | none => "null"
  | some ProofPolicyReject.emptyBlockCarriesProof => "\"empty_block_carries_proof\""
  | some ProofPolicyReject.missingTransactionProofs => "\"missing_transaction_proofs\""
  | some ProofPolicyReject.transactionProofCountMismatch => "\"transaction_proof_count_mismatch\""
  | some ProofPolicyReject.unsupportedInlineRequired => "\"unsupported_inline_required\""
  | some ProofPolicyReject.missingProvenBatch => "\"missing_proven_batch\""
  | some ProofPolicyReject.missingTransactionValidityClaims =>
      "\"missing_transaction_validity_claims\""
  | some ProofPolicyReject.legacyInlineBatch => "\"legacy_inline_batch\""
  | some ProofPolicyReject.recursiveBlockCommitmentProofBytes =>
      "\"recursive_block_commitment_proof_bytes\""
  | some ProofPolicyReject.recursiveBlockReceiptRootPayload =>
      "\"recursive_block_receipt_root_payload\""
  | some ProofPolicyReject.missingRecursiveBlockArtifact =>
      "\"missing_recursive_block_artifact\""
  | some ProofPolicyReject.missingReceiptRootPayload => "\"missing_receipt_root_payload\""

def proofPolicyCaseJson (name : String) (input : ProofPolicyInput) : String :=
  let result := evaluateProofPolicy input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"tx_count\": " ++ toString input.txCount ++ ",\n"
    ++ "      \"verification_mode\": \"" ++ verificationModeJson input.verificationMode ++ "\",\n"
    ++ "      \"has_proven_batch\": " ++ boolJson input.hasProvenBatch ++ ",\n"
    ++ "      \"batch_mode\": \"" ++ batchModeJson input.batchMode ++ "\",\n"
    ++ "      \"commitment_proof_bytes\": " ++ toString input.commitmentProofBytes ++ ",\n"
    ++ "      \"has_block_artifact\": " ++ boolJson input.hasBlockArtifact ++ ",\n"
    ++ "      \"has_receipt_root\": " ++ boolJson input.hasReceiptRoot ++ ",\n"
    ++ "      \"has_tx_validity_artifacts\": " ++ boolJson input.hasTxValidityArtifacts ++ ",\n"
    ++ "      \"tx_validity_artifact_count\": "
    ++ toString input.txValidityArtifactCount ++ ",\n"
    ++ "      \"has_tx_validity_claims\": " ++ boolJson input.hasTxValidityClaims ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def cleanEmpty : ProofPolicyInput :=
  {
    txCount := 0,
    verificationMode := VerificationMode.selfContained,
    hasProvenBatch := false,
    batchMode := BatchMode.recursiveBlock,
    commitmentProofBytes := 0,
    hasBlockArtifact := false,
    hasReceiptRoot := false,
    hasTxValidityArtifacts := false,
    txValidityArtifactCount := 0,
    hasTxValidityClaims := false
  }

def recursiveComplete : ProofPolicyInput :=
  {
    txCount := 2,
    verificationMode := VerificationMode.selfContained,
    hasProvenBatch := true,
    batchMode := BatchMode.recursiveBlock,
    commitmentProofBytes := 0,
    hasBlockArtifact := true,
    hasReceiptRoot := false,
    hasTxValidityArtifacts := true,
    txValidityArtifactCount := 2,
    hasTxValidityClaims := true
  }

def receiptRootComplete : ProofPolicyInput :=
  {
    txCount := 2,
    verificationMode := VerificationMode.selfContained,
    hasProvenBatch := true,
    batchMode := BatchMode.receiptRoot,
    commitmentProofBytes := 256,
    hasBlockArtifact := false,
    hasReceiptRoot := true,
    hasTxValidityArtifacts := true,
    txValidityArtifactCount := 2,
    hasTxValidityClaims := true
  }

def withTxCount (input : ProofPolicyInput) (txCount : Nat) : ProofPolicyInput :=
  { input with txCount }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"proof_policy_cases\": [\n"
    ++ proofPolicyCaseJson "empty-block-without-proof-payloads-accepted" cleanEmpty ++ ",\n"
    ++ proofPolicyCaseJson "empty-block-rejects-proven-batch"
      { cleanEmpty with hasProvenBatch := true } ++ ",\n"
    ++ proofPolicyCaseJson "empty-block-rejects-block-artifact"
      { cleanEmpty with hasBlockArtifact := true } ++ ",\n"
    ++ proofPolicyCaseJson "nonempty-requires-tx-artifacts"
      { recursiveComplete with hasTxValidityArtifacts := false } ++ ",\n"
    ++ proofPolicyCaseJson "nonempty-rejects-tx-artifact-count-mismatch"
      { recursiveComplete with txValidityArtifactCount := 1 } ++ ",\n"
    ++ proofPolicyCaseJson "nonempty-rejects-inline-required-mode"
      { recursiveComplete with verificationMode := VerificationMode.inlineRequired } ++ ",\n"
    ++ proofPolicyCaseJson "nonempty-requires-proven-batch"
      { recursiveComplete with hasProvenBatch := false } ++ ",\n"
    ++ proofPolicyCaseJson "nonempty-requires-tx-validity-claims"
      { recursiveComplete with hasTxValidityClaims := false } ++ ",\n"
    ++ proofPolicyCaseJson "legacy-inline-batch-rejected"
      { recursiveComplete with batchMode := BatchMode.inlineTx } ++ ",\n"
    ++ proofPolicyCaseJson "recursive-block-with-commitment-proof-bytes-rejected"
      { recursiveComplete with commitmentProofBytes := 64 } ++ ",\n"
    ++ proofPolicyCaseJson "recursive-block-with-receipt-root-rejected"
      { recursiveComplete with hasReceiptRoot := true } ++ ",\n"
    ++ proofPolicyCaseJson "recursive-block-requires-block-artifact"
      { recursiveComplete with hasBlockArtifact := false } ++ ",\n"
    ++ proofPolicyCaseJson "recursive-block-complete-accepted" recursiveComplete ++ ",\n"
    ++ proofPolicyCaseJson "receipt-root-requires-receipt-payload"
      { receiptRootComplete with hasReceiptRoot := false } ++ ",\n"
    ++ proofPolicyCaseJson "receipt-root-complete-accepted" receiptRootComplete ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
