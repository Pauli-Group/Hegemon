import Hegemon.Native.StagedProofReload

open Hegemon.Native.StagedProofReload

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option StagedProofReloadReject -> String
  | none => "null"
  | some StagedProofReloadReject.malformedProofKey =>
      "\"malformed_proof_key\""
  | some StagedProofReloadReject.emptyProof =>
      "\"empty_proof\""
  | some StagedProofReloadReject.oversizedProof =>
      "\"oversized_proof\""
  | some StagedProofReloadReject.stagedProofCapacityReached =>
      "\"staged_proof_capacity_reached\""
  | some StagedProofReloadReject.stagedProofByteCapacityReached =>
      "\"staged_proof_byte_capacity_reached\""
  | some StagedProofReloadReject.proofBindingHashMismatch =>
      "\"proof_binding_hash_mismatch\""

def stagedProofReloadCaseJson
    (name : String)
    (input : StagedProofReloadInput) : String :=
  let result := evaluateStagedProofReloadRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"key_well_formed\": "
    ++ boolJson input.keyWellFormed ++ ",\n"
    ++ "      \"proof_nonempty\": "
    ++ boolJson input.proofNonempty ++ ",\n"
    ++ "      \"proof_within_limit\": "
    ++ boolJson input.proofWithinLimit ++ ",\n"
    ++ "      \"capacity_available\": "
    ++ boolJson input.capacityAvailable ++ ",\n"
    ++ "      \"byte_capacity_available\": "
    ++ boolJson input.byteCapacityAvailable ++ ",\n"
    ++ "      \"proof_binding_hash_matches_key\": "
    ++ boolJson input.proofBindingHashMatchesKey ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"staged_proof_reload_cases\": [\n"
    ++ stagedProofReloadCaseJson "valid-staged-proof-reload"
      valid ++ ",\n"
    ++ stagedProofReloadCaseJson "malformed-proof-key-rejected"
      malformedProofKey ++ ",\n"
    ++ stagedProofReloadCaseJson "empty-proof-rejected"
      emptyProof ++ ",\n"
    ++ stagedProofReloadCaseJson "oversized-proof-rejected"
      oversizedProof ++ ",\n"
    ++ stagedProofReloadCaseJson
      "staged-proof-capacity-reached-rejected"
      stagedProofCapacityReached ++ ",\n"
    ++ stagedProofReloadCaseJson
      "staged-proof-byte-capacity-reached-rejected"
      stagedProofByteCapacityReached ++ ",\n"
    ++ stagedProofReloadCaseJson
      "proof-binding-hash-mismatch-rejected"
      proofBindingHashMismatch ++ ",\n"
    ++ stagedProofReloadCaseJson "malformed-key-precedes-empty"
      malformed_key_precedes_empty_input ++ ",\n"
    ++ stagedProofReloadCaseJson "empty-precedes-oversize"
      empty_precedes_oversize_input ++ ",\n"
    ++ stagedProofReloadCaseJson "oversize-precedes-capacity"
      oversize_precedes_capacity_input ++ ",\n"
    ++ stagedProofReloadCaseJson "capacity-precedes-byte-capacity"
      capacity_precedes_byte_capacity_input ++ ",\n"
    ++ stagedProofReloadCaseJson "byte-capacity-precedes-binding-mismatch"
      byte_capacity_precedes_binding_mismatch_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
