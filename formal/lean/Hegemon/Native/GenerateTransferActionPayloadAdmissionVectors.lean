import Hegemon.Native.TransferActionPayloadAdmission

open Hegemon.Native.TransferActionPayloadAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option TransferPayloadReject -> String
  | none => "null"
  | some TransferPayloadReject.proofMissing => "\"proof_missing\""
  | some TransferPayloadReject.proofTooLarge => "\"proof_too_large\""
  | some TransferPayloadReject.anchorMismatch => "\"anchor_mismatch\""
  | some TransferPayloadReject.commitmentsMismatch => "\"commitments_mismatch\""
  | some TransferPayloadReject.inlineCiphertextTooLarge =>
      "\"inline_ciphertext_too_large\""
  | some TransferPayloadReject.ciphertextHashesMismatch =>
      "\"ciphertext_hashes_mismatch\""
  | some TransferPayloadReject.ciphertextSizesMismatch =>
      "\"ciphertext_sizes_mismatch\""
  | some TransferPayloadReject.bindingHashMismatch => "\"binding_hash_mismatch\""
  | some TransferPayloadReject.feeMismatch => "\"fee_mismatch\""

def transferPayloadCaseJson (name : String) (input : TransferPayloadInput) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"proof_bytes\": " ++ toString input.proofBytes ++ ",\n"
    ++ "      \"max_proof_bytes\": " ++ toString input.maxProofBytes ++ ",\n"
    ++ "      \"anchor_matches\": " ++ boolJson input.anchorMatches ++ ",\n"
    ++ "      \"commitments_match\": " ++ boolJson input.commitmentsMatch ++ ",\n"
    ++ "      \"inline_ciphertext_bytes\": " ++ toString input.inlineCiphertextBytes ++ ",\n"
    ++ "      \"max_ciphertext_bytes\": " ++ toString input.maxCiphertextBytes ++ ",\n"
    ++ "      \"ciphertext_hashes_match\": "
      ++ boolJson input.ciphertextHashesMatch ++ ",\n"
    ++ "      \"ciphertext_sizes_match\": "
      ++ boolJson input.ciphertextSizesMatch ++ ",\n"
    ++ "      \"binding_hash_matches\": " ++ boolJson input.bindingHashMatches ++ ",\n"
    ++ "      \"fee_matches\": " ++ boolJson input.feeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (transferPayloadAccepts input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (transferPayloadRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"transfer_action_payload_admission_cases\": [\n"
    ++ transferPayloadCaseJson "valid-transfer-payload"
      validTransferPayload ++ ",\n"
    ++ transferPayloadCaseJson "exact-proof-limit-accepts"
      { validTransferPayload with proofBytes := validTransferPayload.maxProofBytes } ++ ",\n"
    ++ transferPayloadCaseJson "proof-missing-rejected"
      { validTransferPayload with proofBytes := 0 } ++ ",\n"
    ++ transferPayloadCaseJson "proof-too-large-rejected"
      { validTransferPayload with
        proofBytes := validTransferPayload.maxProofBytes + 1 } ++ ",\n"
    ++ transferPayloadCaseJson "anchor-mismatch-rejected"
      { validTransferPayload with anchorMatches := false } ++ ",\n"
    ++ transferPayloadCaseJson "commitments-mismatch-rejected"
      { validTransferPayload with commitmentsMatch := false } ++ ",\n"
    ++ transferPayloadCaseJson "inline-ciphertext-too-large-rejected"
      { validTransferPayload with
        inlineCiphertextBytes := validTransferPayload.maxCiphertextBytes + 1 } ++ ",\n"
    ++ transferPayloadCaseJson "ciphertext-hashes-mismatch-rejected"
      { validTransferPayload with ciphertextHashesMatch := false } ++ ",\n"
    ++ transferPayloadCaseJson "ciphertext-sizes-mismatch-rejected"
      { validTransferPayload with ciphertextSizesMatch := false } ++ ",\n"
    ++ transferPayloadCaseJson "binding-hash-mismatch-rejected"
      { validTransferPayload with bindingHashMatches := false } ++ ",\n"
    ++ transferPayloadCaseJson "fee-mismatch-rejected"
      { validTransferPayload with feeMatches := false } ++ ",\n"
    ++ transferPayloadCaseJson "proof-missing-precedes-anchor"
      { validTransferPayload with proofBytes := 0, anchorMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
