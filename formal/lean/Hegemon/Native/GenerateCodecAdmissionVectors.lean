import Hegemon.Native.CodecAdmission

open Hegemon.Native.CodecAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def syncRejectionJson : Option SyncDecodeReject -> String
  | none => "null"
  | some SyncDecodeReject.wireDecodeRejected => "\"wire_decode_rejected\""
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

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"sync_codec_cases\": [\n"
    ++ syncCaseJson "sync-valid-bounded-wire" "valid_request" validSync ++ ",\n"
    ++ syncCaseJson "sync-legacy-bincode-rejected" "legacy_bincode_request"
      { validSync with boundedWireDecodeAccepts := false, legacyBincodePayload := true } ++ ",\n"
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
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
