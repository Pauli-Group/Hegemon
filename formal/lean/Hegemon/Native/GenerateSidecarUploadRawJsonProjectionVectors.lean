import Hegemon.Native.SidecarUploadRawJsonProjection

open Hegemon.Native.SidecarUploadAdmission
open Hegemon.Native.SidecarUploadRawJsonProjection

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natListJson : List Nat -> String
  | [] => "[]"
  | head :: tail =>
      "[" ++ toString head ++ String.join (tail.map fun value => ", " ++ toString value) ++ "]"

def kindJson : RawSidecarUploadKind -> String
  | RawSidecarUploadKind.ciphertexts => "\"ciphertexts\""
  | RawSidecarUploadKind.proofs => "\"proofs\""

def sidecarRejectJson : SidecarUploadReject -> String
  | SidecarUploadReject.tooManyCiphertexts => "\"too_many_ciphertexts\""
  | SidecarUploadReject.tooManyProofs => "\"too_many_proofs\""
  | SidecarUploadReject.stagedCiphertextCapacityReached =>
      "\"staged_ciphertext_capacity_reached\""
  | SidecarUploadReject.stagedProofCapacityReached =>
      "\"staged_proof_capacity_reached\""
  | SidecarUploadReject.proofBindingHashMissing =>
      "\"proof_binding_hash_missing\""
  | SidecarUploadReject.invalidBindingHash => "\"invalid_binding_hash\""
  | SidecarUploadReject.proofMissing => "\"proof_missing\""
  | SidecarUploadReject.proofEmpty => "\"proof_empty\""
  | SidecarUploadReject.proofTooLarge => "\"proof_too_large\""
  | SidecarUploadReject.proofBindingHashMismatch =>
      "\"proof_binding_hash_mismatch\""

def rejectionJson : Option RawSidecarUploadReject -> String
  | none => "null"
  | some RawSidecarUploadReject.jsonDecodeRejected => "\"json_decode_rejected\""
  | some RawSidecarUploadReject.uploadFieldMissing => "\"upload_field_missing\""
  | some RawSidecarUploadReject.ciphertextBytesRejected =>
      "\"ciphertext_bytes_rejected\""
  | some RawSidecarUploadReject.proofBytesRejected => "\"proof_bytes_rejected\""
  | some (RawSidecarUploadReject.sidecar reject) => sidecarRejectJson reject

def caseJson (name : String) (case : RawSidecarUploadCase) : String :=
  let input := case.input
  let proofMetadata := input.proofMetadata
  let proofDecoded := input.proofDecoded
  let result := evaluateRawSidecarUpload input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": " ++ kindJson input.kind ++ ",\n"
    ++ "      \"raw_json_bytes\": " ++ natListJson case.rawJsonBytes ++ ",\n"
    ++ "      \"json_decode_accepts\": " ++ boolJson input.jsonDecodeAccepts ++ ",\n"
    ++ "      \"upload_field_present\": " ++ boolJson input.uploadFieldPresent ++ ",\n"
    ++ "      \"item_count\": " ++ toString input.requestCount.itemCount ++ ",\n"
    ++ "      \"max_items\": " ++ toString input.requestCount.maxItems ++ ",\n"
    ++ "      \"ciphertext_item_present\": " ++ boolJson input.ciphertextItemPresent ++ ",\n"
    ++ "      \"ciphertext_bytes_decode\": " ++ boolJson input.ciphertextBytesDecode ++ ",\n"
    ++ "      \"proof_item_present\": " ++ boolJson input.proofItemPresent ++ ",\n"
    ++ "      \"binding_hash_present\": " ++ boolJson proofMetadata.bindingHashPresent ++ ",\n"
    ++ "      \"binding_hash_valid\": " ++ boolJson proofMetadata.bindingHashValid ++ ",\n"
    ++ "      \"proof_present\": " ++ boolJson proofMetadata.proofPresent ++ ",\n"
    ++ "      \"proof_bytes_decode\": " ++ boolJson input.proofBytesDecode ++ ",\n"
    ++ "      \"proof_bytes\": " ++ toString proofDecoded.proofBytes ++ ",\n"
    ++ "      \"max_proof_bytes\": " ++ toString proofDecoded.maxProofBytes ++ ",\n"
    ++ "      \"proof_binding_hash_matches_key\": "
      ++ boolJson proofDecoded.proofBindingHashMatchesKey ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"sidecar_upload_raw_json_projection_cases\": [\n"
    ++ caseJson "valid-ciphertext-raw-upload" validCiphertextUpload ++ ",\n"
    ++ caseJson "malformed-ciphertext-raw-json-rejected"
      malformedCiphertextUpload ++ ",\n"
    ++ caseJson "unknown-ciphertext-raw-field-rejected"
      unknownCiphertextFieldUpload ++ ",\n"
    ++ caseJson "missing-ciphertext-field-rejected"
      missingCiphertextFieldUpload ++ ",\n"
    ++ caseJson "non-array-ciphertext-field-rejected"
      nonArrayCiphertextFieldUpload ++ ",\n"
    ++ caseJson "invalid-ciphertext-raw-bytes-rejected"
      invalidCiphertextBytesUpload ++ ",\n"
    ++ caseJson "too-many-ciphertexts-raw-upload-rejected"
      tooManyCiphertextsUpload ++ ",\n"
    ++ caseJson "valid-empty-proof-raw-upload" validEmptyProofUpload ++ ",\n"
    ++ caseJson "missing-proofs-field-rejected" missingProofsFieldUpload ++ ",\n"
    ++ caseJson "non-array-proofs-field-rejected" nonArrayProofsFieldUpload ++ ",\n"
    ++ caseJson "unknown-proof-item-raw-field-rejected"
      unknownProofItemFieldUpload ++ ",\n"
    ++ caseJson "too-many-proofs-raw-upload-rejected" tooManyProofsUpload ++ ",\n"
    ++ caseJson "missing-proof-binding-hash-raw-upload-rejected"
      missingProofBindingHashUpload ++ ",\n"
    ++ caseJson "invalid-proof-binding-hash-raw-upload-rejected"
      invalidProofBindingHashUpload ++ ",\n"
    ++ caseJson "missing-proof-bytes-raw-upload-rejected"
      missingProofBytesUpload ++ ",\n"
    ++ caseJson "invalid-proof-raw-bytes-rejected" invalidProofBytesUpload ++ ",\n"
    ++ caseJson "empty-proof-raw-bytes-rejected" emptyProofBytesUpload ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
