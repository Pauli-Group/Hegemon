import Hegemon.Consensus.ProvenBatchBinding

open Hegemon.Consensus.ProvenBatchBinding

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def batchModeJson : BatchMode -> String
  | BatchMode.inlineTx => "inline_tx"
  | BatchMode.receiptRoot => "receipt_root"
  | BatchMode.recursiveBlock => "recursive_block"

def artifactKindJson : ArtifactKind -> String
  | ArtifactKind.inlineTx => "inline_tx"
  | ArtifactKind.txLeaf => "tx_leaf"
  | ArtifactKind.receiptRoot => "receipt_root"
  | ArtifactKind.recursiveBlockV1 => "recursive_block_v1"
  | ArtifactKind.recursiveBlockV2 => "recursive_block_v2"

def bindingRejectJson : Option BindingReject -> String
  | none => "null"
  | some BindingReject.incompatibleRoute => "\"incompatible_route\""
  | some BindingReject.txCountMismatch => "\"tx_count_mismatch\""
  | some BindingReject.statementCommitmentMismatch => "\"statement_commitment_mismatch\""
  | some BindingReject.daRootMismatch => "\"da_root_mismatch\""
  | some BindingReject.daChunkCountZero => "\"da_chunk_count_zero\""
  | some BindingReject.artifactKindMismatch => "\"artifact_kind_mismatch\""
  | some BindingReject.artifactVerifierProfileMismatch =>
      "\"artifact_verifier_profile_mismatch\""
  | some BindingReject.recursiveBlockReceiptRootPayload =>
      "\"recursive_block_receipt_root_payload\""

def provenBatchBindingCaseJson (name : String) (input : BindingInput) : String :=
  let result := evaluateBinding input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"batch_mode\": \"" ++ batchModeJson input.batchMode ++ "\",\n"
    ++ "      \"proof_kind\": \"" ++ artifactKindJson input.proofKind ++ "\",\n"
    ++ "      \"tx_count\": " ++ toString input.txCount ++ ",\n"
    ++ "      \"expected_tx_count\": " ++ toString input.expectedTxCount ++ ",\n"
    ++ "      \"statement_commitment_matches\": "
    ++ boolJson input.statementCommitmentMatches ++ ",\n"
    ++ "      \"da_root_matches\": " ++ boolJson input.daRootMatches ++ ",\n"
    ++ "      \"da_chunk_count\": " ++ toString input.daChunkCount ++ ",\n"
    ++ "      \"has_artifact\": " ++ boolJson input.hasArtifact ++ ",\n"
    ++ "      \"artifact_kind\": \"" ++ artifactKindJson input.artifactKind ++ "\",\n"
    ++ "      \"artifact_verifier_profile_matches\": "
    ++ boolJson input.artifactVerifierProfileMatches ++ ",\n"
    ++ "      \"has_receipt_root\": " ++ boolJson input.hasReceiptRoot ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ bindingRejectJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"proven_batch_binding_cases\": [\n"
    ++ provenBatchBindingCaseJson
      "valid-recursive-block-v2-binding"
      validRecursiveBlockV2 ++ ",\n"
    ++ provenBatchBindingCaseJson
      "valid-receipt-root-binding-without-artifact"
      validReceiptRoot ++ ",\n"
    ++ provenBatchBindingCaseJson
      "recursive-route-rejects-receipt-root-kind"
      { validRecursiveBlockV2 with proofKind := ArtifactKind.receiptRoot } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "receipt-route-rejects-recursive-block-kind"
      { validReceiptRoot with proofKind := ArtifactKind.recursiveBlockV2 } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "tx-count-mismatch-rejected"
      { validRecursiveBlockV2 with txCount := 1 } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "statement-commitment-mismatch-rejected"
      { validRecursiveBlockV2 with statementCommitmentMatches := false } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "da-root-mismatch-rejected"
      { validRecursiveBlockV2 with daRootMatches := false } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "da-chunk-count-zero-rejected"
      { validRecursiveBlockV2 with daChunkCount := 0 } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "artifact-kind-mismatch-rejected"
      { validRecursiveBlockV2 with artifactKind := ArtifactKind.recursiveBlockV1 } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "artifact-verifier-profile-mismatch-rejected"
      { validRecursiveBlockV2 with artifactVerifierProfileMatches := false } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "recursive-block-receipt-root-payload-rejected"
      { validRecursiveBlockV2 with hasReceiptRoot := true } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "missing-artifact-skips-envelope-checks"
      { validRecursiveBlockV2 with
        hasArtifact := false,
        artifactKind := ArtifactKind.receiptRoot,
        artifactVerifierProfileMatches := false
      } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "recursive-block-v1-route-accepted"
      { validRecursiveBlockV2 with
        proofKind := ArtifactKind.recursiveBlockV1,
        artifactKind := ArtifactKind.recursiveBlockV1
      } ++ ",\n"
    ++ provenBatchBindingCaseJson
      "recursive-route-rejects-tx-leaf-kind"
      { validRecursiveBlockV2 with proofKind := ArtifactKind.txLeaf } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
