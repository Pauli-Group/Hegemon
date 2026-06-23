import Hegemon.Native.BridgeWitnessExportAdmission

open Hegemon.Native.BridgeWitnessExportAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def natOptionJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def rejectionJson : Option BridgeWitnessExportReject -> String
  | none => "null"
  | some BridgeWitnessExportReject.malformedBlockHash =>
      "\"malformed_block_hash\""
  | some BridgeWitnessExportReject.unknownBlock =>
      "\"unknown_block\""
  | some BridgeWitnessExportReject.missingCanonicalHeight =>
      "\"missing_canonical_height\""
  | some BridgeWitnessExportReject.noncanonicalBlock =>
      "\"noncanonical_block\""
  | some BridgeWitnessExportReject.blockActionsDecodeFailed =>
      "\"block_actions_decode_failed\""
  | some BridgeWitnessExportReject.messageIndexOutOfBounds =>
      "\"message_index_out_of_bounds\""
  | some BridgeWitnessExportReject.missingParent =>
      "\"missing_parent\""
  | some BridgeWitnessExportReject.tipBeforeMessage =>
      "\"tip_before_message\""
  | some BridgeWitnessExportReject.explicitHistoryTooLong =>
      "\"explicit_history_too_long\""
  | some BridgeWitnessExportReject.materializedHistoryTooLong =>
      "\"materialized_history_too_long\""

def bridgeWitnessExportCaseJson
    (name : String)
    (input : BridgeWitnessExportInput) : String :=
  let result := evaluateBridgeWitnessExport input
  let confirmations := bridgeWitnessExportConfirmations input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"block_hash_parameter_valid\": "
      ++ boolJson input.blockHashParameterValid ++ ",\n"
    ++ "      \"explicit_block_hash\": "
      ++ boolJson input.explicitBlockHash ++ ",\n"
    ++ "      \"block_known\": " ++ boolJson input.blockKnown ++ ",\n"
    ++ "      \"canonical_height_present\": "
      ++ boolJson input.canonicalHeightPresent ++ ",\n"
    ++ "      \"block_is_canonical\": "
      ++ boolJson input.blockIsCanonical ++ ",\n"
    ++ "      \"block_actions_decoded\": "
      ++ boolJson input.blockActionsDecoded ++ ",\n"
    ++ "      \"message_index_in_bounds\": "
      ++ boolJson input.messageIndexInBounds ++ ",\n"
    ++ "      \"parent_known\": "
      ++ boolJson input.parentKnown ++ ",\n"
    ++ "      \"best_height\": " ++ toString input.bestHeight ++ ",\n"
      ++ "      \"message_height\": " ++ toString input.messageHeight ++ ",\n"
      ++ "      \"max_explicit_history\": "
        ++ toString input.maxExplicitHistory ++ ",\n"
      ++ "      \"max_materialized_history\": "
        ++ toString input.maxMaterializedHistory ++ ",\n"
      ++ "      \"expected_valid\": " ++ boolJson (result.isOk) ++ ",\n"
    ++ "      \"expected_confirmations_checked\": "
      ++ natOptionJson confirmations ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ rejectionJson (bridgeWitnessExportRejection input) ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"bridge_witness_export_admission_cases\": [\n"
    ++ bridgeWitnessExportCaseJson
      "valid-bridge-witness-export" valid ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "same-height-has-one-confirmation" sameHeightValid ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "large-confirmation-count-caps-to-u32-max"
      cappedConfirmationsValid ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "malformed-block-hash-rejected" malformedBlockHash ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "unknown-block-rejected" unknownBlock ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "missing-canonical-height-rejected"
      missingCanonicalHeight ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "noncanonical-block-rejected" noncanonicalBlock ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "block-actions-decode-failed-rejected"
      blockActionsDecodeFailed ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "message-index-out-of-bounds-rejected"
      messageIndexOutOfBounds ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "missing-parent-rejected" missingParent ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "tip-before-message-rejected" tipBeforeMessage ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "explicit-history-too-long-rejected" explicitHistoryTooLong ++ ",\n"
      ++ bridgeWitnessExportCaseJson
        "latest-backscan-rejects-oversized-materialized-history"
        latestBackscanCanExceedExplicitHistoryBound ++ ",\n"
      ++ bridgeWitnessExportCaseJson
        "latest-backscan-at-materialized-history-bound-accepted"
        latestBackscanAtMaterializedHistoryBound ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "malformed-hash-precedes-unknown-block"
      malformed_hash_precedes_unknown_block_input ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "noncanonical-precedes-decode-failure"
      noncanonical_precedes_decode_failure_input ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "message-index-precedes-missing-parent"
      message_index_precedes_missing_parent_input ++ ",\n"
    ++ bridgeWitnessExportCaseJson
      "missing-parent-precedes-tip-before-message"
      missing_parent_precedes_tip_before_message_input ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
