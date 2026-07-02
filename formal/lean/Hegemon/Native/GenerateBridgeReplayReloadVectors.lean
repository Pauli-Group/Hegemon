import Hegemon.Native.BridgeReplayReload

open Hegemon.Native.BridgeReplayReload

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option BridgeReplayReloadReject -> String
  | none => "null"
  | some BridgeReplayReloadReject.malformedReplayKey =>
      "\"malformed_replay_key\""
  | some BridgeReplayReloadReject.invalidReplayMarker =>
      "\"invalid_replay_marker\""
  | some BridgeReplayReloadReject.canonicalReplayDuplicate =>
      "\"canonical_replay_duplicate\""
  | some BridgeReplayReloadReject.missingConsumedReplayKey =>
      "\"missing_consumed_replay_key\""
  | some BridgeReplayReloadReject.extraConsumedReplayKey =>
      "\"extra_consumed_replay_key\""

def bridgeReplayReloadCaseJson
    (name : String)
    (input : BridgeReplayReloadInput) : String :=
  let result := evaluateBridgeReplayReloadRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"replay_keys_well_formed\": "
    ++ boolJson input.replayKeysWellFormed ++ ",\n"
    ++ "      \"replay_markers_valid\": "
    ++ boolJson input.replayMarkersValid ++ ",\n"
    ++ "      \"canonical_replay_keys_unique\": "
    ++ boolJson input.canonicalReplayKeysUnique ++ ",\n"
    ++ "      \"no_missing_loaded_replay_keys\": "
    ++ boolJson input.noMissingLoadedReplayKeys ++ ",\n"
    ++ "      \"no_extra_loaded_replay_keys\": "
    ++ boolJson input.noExtraLoadedReplayKeys ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_replay_reload_cases\": [\n"
    ++ bridgeReplayReloadCaseJson "valid-bridge-replay-reload" valid ++ ",\n"
    ++ bridgeReplayReloadCaseJson "malformed-replay-key-rejected"
      malformedReplayKey ++ ",\n"
    ++ bridgeReplayReloadCaseJson "invalid-replay-marker-rejected"
      invalidReplayMarker ++ ",\n"
    ++ bridgeReplayReloadCaseJson "canonical-replay-duplicate-rejected"
      canonicalReplayDuplicate ++ ",\n"
    ++ bridgeReplayReloadCaseJson "missing-consumed-replay-key-rejected"
      missingConsumedReplayKey ++ ",\n"
    ++ bridgeReplayReloadCaseJson "extra-consumed-replay-key-rejected"
      extraConsumedReplayKey ++ ",\n"
    ++ bridgeReplayReloadCaseJson "malformed-key-precedes-marker"
      malformed_key_precedes_marker_input ++ ",\n"
    ++ bridgeReplayReloadCaseJson "marker-precedes-canonical-duplicate"
      marker_precedes_canonical_duplicate_input ++ ",\n"
    ++ bridgeReplayReloadCaseJson "canonical-duplicate-precedes-missing"
      canonical_duplicate_precedes_missing_input ++ ",\n"
    ++ bridgeReplayReloadCaseJson "missing-precedes-extra"
      missing_precedes_extra_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
