import Hegemon.Native.StagedCiphertextReload

open Hegemon.Native.StagedCiphertextReload

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option StagedCiphertextReloadReject -> String
  | none => "null"
  | some StagedCiphertextReloadReject.malformedCiphertextKey =>
      "\"malformed_ciphertext_key\""
  | some StagedCiphertextReloadReject.oversizedCiphertext =>
      "\"oversized_ciphertext\""
  | some StagedCiphertextReloadReject.ciphertextHashMismatch =>
      "\"ciphertext_hash_mismatch\""
  | some StagedCiphertextReloadReject.stagedCiphertextCapacityReached =>
      "\"staged_ciphertext_capacity_reached\""

def stagedCiphertextReloadCaseJson
    (name : String)
    (input : StagedCiphertextReloadInput) : String :=
  let result := evaluateStagedCiphertextReloadRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"key_well_formed\": "
    ++ boolJson input.keyWellFormed ++ ",\n"
    ++ "      \"ciphertext_within_limit\": "
    ++ boolJson input.ciphertextWithinLimit ++ ",\n"
    ++ "      \"ciphertext_hash_matches_key\": "
    ++ boolJson input.ciphertextHashMatchesKey ++ ",\n"
    ++ "      \"capacity_available\": "
    ++ boolJson input.capacityAvailable ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"staged_ciphertext_reload_cases\": [\n"
    ++ stagedCiphertextReloadCaseJson "valid-staged-ciphertext-reload"
      valid ++ ",\n"
    ++ stagedCiphertextReloadCaseJson "malformed-ciphertext-key-rejected"
      malformedCiphertextKey ++ ",\n"
    ++ stagedCiphertextReloadCaseJson "oversized-ciphertext-rejected"
      oversizedCiphertext ++ ",\n"
    ++ stagedCiphertextReloadCaseJson "ciphertext-hash-mismatch-rejected"
      ciphertextHashMismatch ++ ",\n"
    ++ stagedCiphertextReloadCaseJson
      "staged-ciphertext-capacity-reached-rejected"
      stagedCiphertextCapacityReached ++ ",\n"
    ++ stagedCiphertextReloadCaseJson "malformed-key-precedes-oversize"
      malformed_key_precedes_oversize_input ++ ",\n"
    ++ stagedCiphertextReloadCaseJson "oversize-precedes-hash-mismatch"
      oversize_precedes_hash_mismatch_input ++ ",\n"
    ++ stagedCiphertextReloadCaseJson "hash-mismatch-precedes-capacity"
      hash_mismatch_precedes_capacity_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
