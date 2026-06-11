import Hegemon.Native.PendingActionReload

open Hegemon.Native.PendingActionReload

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option PendingActionReloadReject -> String
  | none => "null"
  | some PendingActionReloadReject.malformedActionKey =>
      "\"malformed_action_key\""
  | some PendingActionReloadReject.keyHashMismatch =>
      "\"key_hash_mismatch\""
  | some PendingActionReloadReject.recomputedHashMismatch =>
      "\"recomputed_hash_mismatch\""
  | some PendingActionReloadReject.duplicatePendingAction =>
      "\"duplicate_pending_action\""

def pendingActionReloadCaseJson
    (name : String)
    (input : PendingActionReloadInput) : String :=
  let result := evaluatePendingActionReloadRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"key_well_formed\": "
    ++ boolJson input.keyWellFormed ++ ",\n"
    ++ "      \"embedded_hash_matches_key\": "
    ++ boolJson input.embeddedHashMatchesKey ++ ",\n"
    ++ "      \"recomputed_hash_matches_embedded\": "
    ++ boolJson input.recomputedHashMatchesEmbedded ++ ",\n"
    ++ "      \"action_hash_unique\": "
    ++ boolJson input.actionHashUnique ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"pending_action_reload_cases\": [\n"
    ++ pendingActionReloadCaseJson "valid-pending-action-reload"
      valid ++ ",\n"
    ++ pendingActionReloadCaseJson "malformed-action-key-rejected"
      malformedActionKey ++ ",\n"
    ++ pendingActionReloadCaseJson "key-hash-mismatch-rejected"
      keyHashMismatch ++ ",\n"
    ++ pendingActionReloadCaseJson "recomputed-hash-mismatch-rejected"
      recomputedHashMismatch ++ ",\n"
    ++ pendingActionReloadCaseJson "duplicate-pending-action-rejected"
      duplicatePendingAction ++ ",\n"
    ++ pendingActionReloadCaseJson "malformed-key-precedes-key-hash-mismatch"
      malformed_key_precedes_key_hash_mismatch_input ++ ",\n"
    ++ pendingActionReloadCaseJson
      "key-hash-mismatch-precedes-recomputed-hash-mismatch"
      key_hash_mismatch_precedes_recomputed_hash_mismatch_input ++ ",\n"
    ++ pendingActionReloadCaseJson
      "recomputed-hash-mismatch-precedes-duplicate"
      recomputed_hash_mismatch_precedes_duplicate_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
