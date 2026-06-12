import Hegemon.Native.SidecarUploadAdmission

open Hegemon.Native.SidecarUploadAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option SidecarUploadReject -> String
  | none => "null"
  | some SidecarUploadReject.tooManyCiphertexts => "\"too_many_ciphertexts\""
  | some SidecarUploadReject.tooManyProofs => "\"too_many_proofs\""
  | some SidecarUploadReject.stagedCiphertextCapacityReached =>
      "\"staged_ciphertext_capacity_reached\""
  | some SidecarUploadReject.stagedProofCapacityReached =>
      "\"staged_proof_capacity_reached\""
  | some SidecarUploadReject.proofBindingHashMissing =>
      "\"proof_binding_hash_missing\""
  | some SidecarUploadReject.invalidBindingHash => "\"invalid_binding_hash\""
  | some SidecarUploadReject.proofMissing => "\"proof_missing\""
  | some SidecarUploadReject.proofEmpty => "\"proof_empty\""
  | some SidecarUploadReject.proofTooLarge => "\"proof_too_large\""
  | some SidecarUploadReject.proofBindingHashMismatch =>
      "\"proof_binding_hash_mismatch\""

def requestCaseJson
    (name : String)
    (kind : String)
    (input : RequestCountInput)
    (result : Except SidecarUploadReject Unit) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": \"" ++ kind ++ "\",\n"
    ++ "      \"item_count\": " ++ toString input.itemCount ++ ",\n"
    ++ "      \"max_items\": " ++ toString input.maxItems ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (accepts result) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson (rejection result) ++ "\n"
    ++ "    }"

def capacityCaseJson
    (name : String)
    (kind : String)
    (input : CapacityInput)
    (result : Except SidecarUploadReject Unit) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"kind\": \"" ++ kind ++ "\",\n"
    ++ "      \"staged_count\": " ++ toString input.stagedCount ++ ",\n"
    ++ "      \"max_staged_count\": " ++ toString input.maxStagedCount ++ ",\n"
    ++ "      \"replaces_existing\": " ++ boolJson input.replacesExisting ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (accepts result) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson (rejection result) ++ "\n"
    ++ "    }"

def metadataCaseJson (name : String) (input : ProofMetadataInput) : String :=
  let result := evaluateProofMetadata input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"binding_hash_present\": " ++ boolJson input.bindingHashPresent ++ ",\n"
    ++ "      \"binding_hash_valid\": " ++ boolJson input.bindingHashValid ++ ",\n"
    ++ "      \"proof_present\": " ++ boolJson input.proofPresent ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (accepts result) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson (rejection result) ++ "\n"
    ++ "    }"

def decodedCaseJson (name : String) (input : ProofDecodedInput) : String :=
  let result := evaluateProofDecoded input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"proof_bytes\": " ++ toString input.proofBytes ++ ",\n"
    ++ "      \"max_proof_bytes\": " ++ toString input.maxProofBytes ++ ",\n"
    ++ "      \"proof_binding_hash_matches_key\": "
    ++ boolJson input.proofBindingHashMatchesKey ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (accepts result) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson (rejection result) ++ "\n"
    ++ "    }"

def belowCapacity : CapacityInput :=
  {
    stagedCount := 3,
    maxStagedCount := 4,
    replacesExisting := false
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"request_count_cases\": [\n"
    ++ requestCaseJson "ciphertexts-empty-accepted" "ciphertexts"
      { itemCount := 0, maxItems := 4 }
      (evaluateCiphertextRequest { itemCount := 0, maxItems := 4 }) ++ ",\n"
    ++ requestCaseJson "ciphertexts-exact-limit-accepted" "ciphertexts"
      requestExactLimit (evaluateCiphertextRequest requestExactLimit) ++ ",\n"
    ++ requestCaseJson "ciphertexts-too-many-rejected" "ciphertexts"
      requestTooMany (evaluateCiphertextRequest requestTooMany) ++ ",\n"
    ++ requestCaseJson "proofs-empty-accepted" "proofs"
      { itemCount := 0, maxItems := 4 }
      (evaluateProofRequest { itemCount := 0, maxItems := 4 }) ++ ",\n"
    ++ requestCaseJson "proofs-exact-limit-accepted" "proofs"
      requestExactLimit (evaluateProofRequest requestExactLimit) ++ ",\n"
    ++ requestCaseJson "proofs-too-many-rejected" "proofs"
      requestTooMany (evaluateProofRequest requestTooMany) ++ "\n"
    ++ "  ],\n"
    ++ "  \"capacity_cases\": [\n"
    ++ capacityCaseJson "ciphertext-new-below-capacity-accepted" "ciphertext"
      belowCapacity (evaluateCiphertextCapacity belowCapacity) ++ ",\n"
    ++ capacityCaseJson "ciphertext-new-at-capacity-rejected" "ciphertext"
      newAtCapacity (evaluateCiphertextCapacity newAtCapacity) ++ ",\n"
    ++ capacityCaseJson "ciphertext-replacement-at-capacity-accepted" "ciphertext"
      replacementAtCapacity (evaluateCiphertextCapacity replacementAtCapacity) ++ ",\n"
    ++ capacityCaseJson "proof-new-below-capacity-accepted" "proof"
      belowCapacity (evaluateProofCapacity belowCapacity) ++ ",\n"
    ++ capacityCaseJson "proof-new-at-capacity-rejected" "proof"
      newAtCapacity (evaluateProofCapacity newAtCapacity) ++ ",\n"
    ++ capacityCaseJson "proof-replacement-at-capacity-accepted" "proof"
      replacementAtCapacity (evaluateProofCapacity replacementAtCapacity) ++ "\n"
    ++ "  ],\n"
    ++ "  \"proof_metadata_cases\": [\n"
    ++ metadataCaseJson "valid-proof-metadata" validProofMetadata ++ ",\n"
    ++ metadataCaseJson "missing-binding-hash-rejected"
      { validProofMetadata with bindingHashPresent := false } ++ ",\n"
    ++ metadataCaseJson "invalid-binding-hash-rejected"
      { validProofMetadata with bindingHashValid := false } ++ ",\n"
    ++ metadataCaseJson "proof-missing-rejected"
      { validProofMetadata with proofPresent := false } ++ ",\n"
    ++ metadataCaseJson "missing-binding-precedes-missing-proof"
      { validProofMetadata with
        bindingHashPresent := false,
        proofPresent := false } ++ ",\n"
    ++ metadataCaseJson "invalid-binding-precedes-missing-proof"
      { validProofMetadata with
        bindingHashValid := false,
        proofPresent := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"proof_decoded_cases\": [\n"
    ++ decodedCaseJson "valid-proof-decoded" validProofDecoded ++ ",\n"
    ++ decodedCaseJson "proof-exact-limit-accepted"
      { validProofDecoded with proofBytes := validProofDecoded.maxProofBytes } ++ ",\n"
    ++ decodedCaseJson "proof-empty-rejected"
      { validProofDecoded with proofBytes := 0 } ++ ",\n"
    ++ decodedCaseJson "proof-too-large-rejected"
      { validProofDecoded with proofBytes := validProofDecoded.maxProofBytes + 1 } ++ ",\n"
    ++ decodedCaseJson "proof-binding-hash-mismatch-rejected"
      { validProofDecoded with proofBindingHashMatchesKey := false } ++ ",\n"
    ++ decodedCaseJson "proof-too-large-precedes-binding-mismatch"
      { validProofDecoded with
        proofBytes := validProofDecoded.maxProofBytes + 1,
        proofBindingHashMatchesKey := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
