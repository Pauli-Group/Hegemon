import Hegemon.Native.StorageDurabilityAdmission

open Hegemon.Native.StorageDurabilityAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option StorageDurabilityReject -> String
  | none => "null"
  | some StorageDurabilityReject.transactionRejected =>
      "\"transaction_rejected\""
  | some StorageDurabilityReject.durabilityFlushFailed =>
      "\"durability_flush_failed\""

def caseJson (name operation : String) (input : StorageDurabilityInput) : String :=
  let result := evaluateStorageDurabilityRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"operation\": \"" ++ operation ++ "\",\n"
    ++ "      \"transaction_accepted\": " ++ boolJson input.transactionAccepted ++ ",\n"
    ++ "      \"durability_flushed\": " ++ boolJson input.durabilityFlushed ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"storage_durability_admission_cases\": [\n"
    ++ caseJson "mined-commit-durable" "mined_block_commit" valid ++ ",\n"
    ++ caseJson "reorg-commit-durable" "canonical_reorg_commit" valid ++ ",\n"
    ++ caseJson "index-repair-durable" "canonical_index_repair" valid ++ ",\n"
    ++ caseJson "noncanonical-record-durable" "noncanonical_block_record" valid ++ ",\n"
    ++ caseJson "pending-action-stage-durable" "pending_action_stage" valid ++ ",\n"
    ++ caseJson "ciphertext-sidecar-stage-durable" "ciphertext_sidecar_stage" valid ++ ",\n"
    ++ caseJson "proof-sidecar-stage-durable" "proof_sidecar_stage" valid ++ ",\n"
    ++ caseJson "genesis-bootstrap-durable" "genesis_bootstrap" valid ++ ",\n"
    ++ caseJson "genesis-marker-repair-durable" "genesis_marker_repair" valid ++ ",\n"
    ++ caseJson "startup-staged-ciphertext-repair-durable"
      "startup_staged_ciphertext_repair"
      valid ++ ",\n"
    ++ caseJson "startup-staged-proof-repair-durable"
      "startup_staged_proof_repair"
      valid ++ ",\n"
    ++ caseJson "startup-pending-action-repair-durable"
      "startup_pending_action_repair"
      valid ++ ",\n"
    ++ caseJson "transaction-rejection-precedes-flush"
      "mined_block_commit"
      { transactionAccepted := false, durabilityFlushed := false } ++ ",\n"
    ++ caseJson "durability-flush-failure-rejected"
      "canonical_reorg_commit"
      { transactionAccepted := true, durabilityFlushed := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
