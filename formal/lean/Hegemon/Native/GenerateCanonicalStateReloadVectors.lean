import Hegemon.Native.CanonicalStateReload

open Hegemon.Native.CanonicalStateReload

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option CanonicalStateReloadReject -> String
  | none => "null"
  | some CanonicalStateReloadReject.malformedNullifierKey =>
      "\"malformed_nullifier_key\""
  | some CanonicalStateReloadReject.invalidNullifierMarker =>
      "\"invalid_nullifier_marker\""
  | some CanonicalStateReloadReject.malformedCommitmentKey =>
      "\"malformed_commitment_key\""
  | some CanonicalStateReloadReject.malformedCommitmentValue =>
      "\"malformed_commitment_value\""
  | some CanonicalStateReloadReject.commitmentIndexGap =>
      "\"commitment_index_gap\""
  | some CanonicalStateReloadReject.commitmentTreeRebuildFailed =>
      "\"commitment_tree_rebuild_failed\""
  | some CanonicalStateReloadReject.commitmentRootMismatch =>
      "\"commitment_root_mismatch\""
  | some CanonicalStateReloadReject.nullifierRootMismatch =>
      "\"nullifier_root_mismatch\""

def canonicalStateReloadCaseJson
    (name : String)
    (input : CanonicalStateReloadInput) : String :=
  let result := evaluateCanonicalStateReloadRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"nullifier_keys_well_formed\": "
    ++ boolJson input.nullifierKeysWellFormed ++ ",\n"
    ++ "      \"nullifier_markers_valid\": "
    ++ boolJson input.nullifierMarkersValid ++ ",\n"
    ++ "      \"commitment_keys_well_formed\": "
    ++ boolJson input.commitmentKeysWellFormed ++ ",\n"
    ++ "      \"commitment_values_well_formed\": "
    ++ boolJson input.commitmentValuesWellFormed ++ ",\n"
    ++ "      \"commitment_indexes_contiguous\": "
    ++ boolJson input.commitmentIndexesContiguous ++ ",\n"
    ++ "      \"commitment_tree_rebuilt\": "
    ++ boolJson input.commitmentTreeRebuilt ++ ",\n"
    ++ "      \"commitment_root_matches_best\": "
    ++ boolJson input.commitmentRootMatchesBest ++ ",\n"
    ++ "      \"nullifier_root_matches_best\": "
    ++ boolJson input.nullifierRootMatchesBest ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"canonical_state_reload_cases\": [\n"
    ++ canonicalStateReloadCaseJson "valid-canonical-state-reload" valid ++ ",\n"
    ++ canonicalStateReloadCaseJson "malformed-nullifier-key-rejected"
      malformedNullifierKey ++ ",\n"
    ++ canonicalStateReloadCaseJson "invalid-nullifier-marker-rejected"
      invalidNullifierMarker ++ ",\n"
    ++ canonicalStateReloadCaseJson "malformed-commitment-key-rejected"
      malformedCommitmentKey ++ ",\n"
    ++ canonicalStateReloadCaseJson "malformed-commitment-value-rejected"
      malformedCommitmentValue ++ ",\n"
    ++ canonicalStateReloadCaseJson "commitment-index-gap-rejected"
      commitmentIndexGap ++ ",\n"
    ++ canonicalStateReloadCaseJson "commitment-tree-rebuild-failed"
      commitmentTreeRebuildFailed ++ ",\n"
    ++ canonicalStateReloadCaseJson "commitment-root-mismatch-rejected"
      commitmentRootMismatch ++ ",\n"
    ++ canonicalStateReloadCaseJson "nullifier-root-mismatch-rejected"
      nullifierRootMismatch ++ ",\n"
    ++ canonicalStateReloadCaseJson "nullifier-key-precedes-commitment-key"
      nullifier_key_precedes_commitment_key_input ++ ",\n"
    ++ canonicalStateReloadCaseJson "commitment-key-precedes-commitment-value"
      commitment_key_precedes_commitment_value_input ++ ",\n"
    ++ canonicalStateReloadCaseJson "commitment-root-precedes-nullifier-root"
      commitment_root_precedes_nullifier_root_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
