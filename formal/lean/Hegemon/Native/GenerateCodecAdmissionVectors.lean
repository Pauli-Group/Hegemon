import Hegemon.Native.CodecAdmission

open Hegemon.Native.CodecAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def syncRejectionJson : Option SyncDecodeReject -> String
  | none => "null"
  | some SyncDecodeReject.wireDecodeRejected => "\"wire_decode_rejected\""
  | some SyncDecodeReject.legacyBincodePayload => "\"legacy_bincode_payload\""
  | some SyncDecodeReject.trailingBytes => "\"trailing_bytes\""

def exactRejectionJson : Option ExactDecodeReject -> String
  | none => "null"
  | some ExactDecodeReject.parserRejected => "\"parser_rejected\""
  | some ExactDecodeReject.trailingBytes => "\"trailing_bytes\""
  | some ExactDecodeReject.nonCanonicalEncoding => "\"non_canonical_encoding\""

def blockActionRejectionJson : Option BlockActionDecodeReject -> String
  | none => "null"
  | some BlockActionDecodeReject.actionCountMismatch => "\"action_count_mismatch\""
  | some BlockActionDecodeReject.actionDecodeNotExact => "\"action_decode_not_exact\""

def nativeMetadataSourceJson : Option NativeMetadataDecodeSource -> String
  | none => "null"
  | some .current => "\"current\""
  | some .legacy => "\"legacy\""

def nativeMetadataRejectionJson : Except NativeMetadataDecodeReject NativeMetadataDecodeSource -> String
  | Except.ok _ => "null"
  | Except.error .currentAndLegacyRejected =>
      "\"current_and_legacy_rejected\""

def nativeMetadataBincodeBudgetRejectionJson :
    Option NativeMetadataBincodeBudgetReject -> String
  | none => "null"
  | some .metadataBytesOverLimit => "\"metadata_bytes_over_limit\""
  | some .actionCountOverLimit => "\"action_count_over_limit\""
  | some .actionPayloadOverLimit => "\"action_payload_over_limit\""
  | some .actionPayloadBytesOverLimit => "\"action_payload_bytes_over_limit\""
  | some .minerPublicKeyOverLimit => "\"miner_public_key_over_limit\""
  | some .minerSignatureOverLimit => "\"miner_signature_over_limit\""

def syncCaseJson (name fixture : String) (input : SyncDecodeInput) : String :=
  let result := evaluateSyncDecodeRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"bounded_wire_decode_accepts\": " ++ boolJson input.boundedWireDecodeAccepts ++ ",\n"
    ++ "      \"consumed_all_bytes\": " ++ boolJson input.consumedAllBytes ++ ",\n"
    ++ "      \"legacy_bincode_payload\": " ++ boolJson input.legacyBincodePayload ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ syncRejectionJson result ++ "\n"
    ++ "    }"

def exactCaseJson (name codec fixture : String) (input : ExactDecodeInput) : String :=
  let result := evaluateExactDecodeRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"codec\": \"" ++ codec ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"parser_accepts\": " ++ boolJson input.parserAccepts ++ ",\n"
    ++ "      \"consumed_all_bytes\": " ++ boolJson input.consumedAllBytes ++ ",\n"
    ++ "      \"canonical_reencode_matches\": " ++ boolJson input.canonicalReencodeMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ exactRejectionJson result ++ "\n"
    ++ "    }"

def blockActionCaseJson (name fixture : String) (input : BlockActionDecodeInput) : String :=
  let result := evaluateBlockActionDecodeRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"declared_tx_count\": " ++ toString input.declaredTxCount ++ ",\n"
    ++ "      \"actual_action_payload_count\": " ++ toString input.actualActionPayloadCount ++ ",\n"
    ++ "      \"every_action_decodes_exactly\": " ++ boolJson input.everyActionDecodesExactly ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ blockActionRejectionJson result ++ "\n"
    ++ "    }"

def nativeMetadataCaseJson
    (name fixture : String) (input : NativeMetadataDecodeInput) : String :=
  let result := evaluateNativeMetadataDecode input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"current_parser_accepts\": "
      ++ boolJson input.currentExact.parserAccepts ++ ",\n"
    ++ "      \"current_consumed_all_bytes\": "
      ++ boolJson input.currentExact.consumedAllBytes ++ ",\n"
    ++ "      \"current_canonical_reencode_matches\": "
      ++ boolJson input.currentExact.canonicalReencodeMatches ++ ",\n"
    ++ "      \"legacy_parser_accepts\": "
      ++ boolJson input.legacyExact.parserAccepts ++ ",\n"
    ++ "      \"legacy_consumed_all_bytes\": "
      ++ boolJson input.legacyExact.consumedAllBytes ++ ",\n"
    ++ "      \"legacy_canonical_reencode_matches\": "
      ++ boolJson input.legacyExact.canonicalReencodeMatches ++ ",\n"
    ++ "      \"expected_valid\": "
      ++ boolJson (nativeMetadataDecodeAccepts input) ++ ",\n"
    ++ "      \"expected_source\": "
      ++ nativeMetadataSourceJson (nativeMetadataDecodeSource input) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ nativeMetadataRejectionJson result ++ "\n"
    ++ "    }"

def nativeMetadataBincodeBudgetCaseJson
    (name fixture : String)
    (input : NativeMetadataBincodeBudgetInput) : String :=
  let result := evaluateNativeMetadataBincodeBudgetRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"fixture\": \"" ++ fixture ++ "\",\n"
    ++ "      \"metadata_bytes\": " ++ toString input.metadataBytes ++ ",\n"
    ++ "      \"max_metadata_bytes\": " ++ toString input.maxMetadataBytes ++ ",\n"
    ++ "      \"action_count\": " ++ toString input.actionCount ++ ",\n"
    ++ "      \"max_action_count\": " ++ toString input.maxActionCount ++ ",\n"
    ++ "      \"largest_action_payload_bytes\": "
      ++ toString input.largestActionPayloadBytes ++ ",\n"
    ++ "      \"max_action_payload_bytes\": "
      ++ toString input.maxActionPayloadBytes ++ ",\n"
    ++ "      \"action_payload_bytes_total\": "
      ++ toString input.actionPayloadBytesTotal ++ ",\n"
    ++ "      \"max_action_payload_bytes_total\": "
      ++ toString input.maxActionPayloadBytesTotal ++ ",\n"
    ++ "      \"miner_public_key_bytes\": "
      ++ toString input.minerPublicKeyBytes ++ ",\n"
    ++ "      \"max_miner_public_key_bytes\": "
      ++ toString input.maxMinerPublicKeyBytes ++ ",\n"
    ++ "      \"miner_signature_bytes\": "
      ++ toString input.minerSignatureBytes ++ ",\n"
    ++ "      \"max_miner_signature_bytes\": "
      ++ toString input.maxMinerSignatureBytes ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": "
      ++ nativeMetadataBincodeBudgetRejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 3,\n"
    ++ "  \"sync_codec_cases\": [\n"
    ++ syncCaseJson "sync-valid-bounded-wire" "valid_request" validSync ++ ",\n"
    ++ syncCaseJson "sync-legacy-bincode-rejected" "legacy_bincode_request"
      { validSync with legacyBincodePayload := true } ++ ",\n"
    ++ syncCaseJson "sync-trailing-byte-rejected" "valid_request_trailing"
      { validSync with consumedAllBytes := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"exact_decode_cases\": [\n"
    ++ exactCaseJson "scale-pending-action-valid" "scale_pending_action" "valid_pending_action"
      validExactDecode ++ ",\n"
    ++ exactCaseJson "scale-pending-action-trailing" "scale_pending_action" "trailing_pending_action"
      { validExactDecode with consumedAllBytes := false } ++ ",\n"
    ++ exactCaseJson "scale-noncanonical-rejected" "scale_normalizing_fixture" "noncanonical_byte"
      { validExactDecode with canonicalReencodeMatches := false } ++ ",\n"
    ++ exactCaseJson "bincode-native-meta-valid" "bincode_native_meta" "valid_genesis_meta"
      validExactDecode ++ ",\n"
    ++ exactCaseJson "bincode-native-meta-trailing" "bincode_native_meta" "trailing_genesis_meta"
      { validExactDecode with consumedAllBytes := false } ++ ",\n"
    ++ exactCaseJson "bincode-noncanonical-rejected" "bincode_normalizing_fixture" "noncanonical_byte"
      { validExactDecode with canonicalReencodeMatches := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"block_action_decode_cases\": [\n"
    ++ blockActionCaseJson "block-actions-valid" "valid_one_action" validBlockActions ++ ",\n"
    ++ blockActionCaseJson "block-actions-count-mismatch-rejected" "count_mismatch"
      { validBlockActions with actualActionPayloadCount := 0 } ++ ",\n"
    ++ blockActionCaseJson "block-actions-trailing-action-rejected" "trailing_action_payload"
      { validBlockActions with everyActionDecodesExactly := false } ++ "\n"
    ++ "  ],\n"
    ++ "  \"native_metadata_decode_cases\": [\n"
    ++ nativeMetadataCaseJson
      "native-metadata-current-selects-current"
      "current_signed_meta"
      validNativeMetadataCurrent ++ ",\n"
    ++ nativeMetadataCaseJson
      "native-metadata-legacy-fallback-selects-legacy"
      "legacy_unsigned_meta"
      validNativeMetadataLegacy ++ ",\n"
    ++ nativeMetadataCaseJson
      "native-metadata-current-trailing-rejects"
      "current_signed_meta_trailing"
      trailingNativeMetadataCurrent ++ ",\n"
    ++ nativeMetadataCaseJson
      "native-metadata-legacy-trailing-rejects"
      "legacy_unsigned_meta_trailing"
      trailingNativeMetadataLegacy ++ "\n"
    ++ "  ],\n"
    ++ "  \"native_metadata_bincode_budget_cases\": [\n"
    ++ nativeMetadataBincodeBudgetCaseJson
      "native-metadata-bincode-budget-valid"
      "valid_current_metadata"
      validNativeMetadataBincodeBudget ++ ",\n"
    ++ nativeMetadataBincodeBudgetCaseJson
      "native-metadata-bincode-budget-metadata-overrun"
      "metadata_bytes_overrun"
      { validNativeMetadataBincodeBudget with
        metadataBytes := productionMaxNativeMetadataBytes + 1 } ++ ",\n"
    ++ nativeMetadataBincodeBudgetCaseJson
      "native-metadata-bincode-budget-action-count-overrun"
      "action_count_overrun"
      { validNativeMetadataBincodeBudget with
        actionCount := productionMaxNativeBlockActions + 1 } ++ ",\n"
    ++ nativeMetadataBincodeBudgetCaseJson
      "native-metadata-bincode-budget-action-payload-overrun"
      "action_payload_overrun"
      { validNativeMetadataBincodeBudget with
        actionCount := 1,
        largestActionPayloadBytes := productionMaxNativeBlockActionPayloadBytes + 1,
        actionPayloadBytesTotal := productionMaxNativeBlockActionPayloadBytes + 1 } ++ ",\n"
    ++ nativeMetadataBincodeBudgetCaseJson
      "native-metadata-bincode-budget-action-total-overrun"
      "action_payload_bytes_overrun"
      { validNativeMetadataBincodeBudget with
        actionCount := productionMaxNativeBlockActions,
        largestActionPayloadBytes := productionMaxNativeBlockActionPayloadBytes,
        actionPayloadBytesTotal := productionMaxNativeBlockActionBytes + 1 } ++ ",\n"
    ++ nativeMetadataBincodeBudgetCaseJson
      "native-metadata-bincode-budget-miner-key-overrun"
      "miner_public_key_overrun"
      { validNativeMetadataBincodeBudget with
        minerPublicKeyBytes := productionMaxMlDsaPublicKeyBytes + 1 } ++ ",\n"
    ++ nativeMetadataBincodeBudgetCaseJson
      "native-metadata-bincode-budget-miner-signature-overrun"
      "miner_signature_overrun"
      { validNativeMetadataBincodeBudget with
        minerSignatureBytes := productionMaxMlDsaSignatureBytes + 1 } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
