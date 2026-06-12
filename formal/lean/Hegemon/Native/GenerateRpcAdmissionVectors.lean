import Hegemon.Native.RpcAdmission

open Hegemon.Native.RpcAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def nullableStringJson (value : Option String) : String :=
  match value with
  | none => "null"
  | some raw => "\"" ++ raw ++ "\""

def policyJson : RpcPolicy -> String
  | RpcPolicy.safeOnly => "\"safe\""
  | RpcPolicy.unsafeAllowed => "\"unsafe\""

def rawPolicyTagJson : RawRpcPolicy -> String
  | RawRpcPolicy.safeToken => "\"safe\""
  | RawRpcPolicy.unsafeToken => "\"unsafe\""
  | RawRpcPolicy.autoToken => "\"auto\""
  | RawRpcPolicy.emptyToken => "\"empty\""
  | RawRpcPolicy.invalidToken => "\"invalid\""

def policyRejectionJson : Except RpcPolicyReject RpcPolicy -> String
  | Except.ok _ => "null"
  | Except.error RpcPolicyReject.invalidPolicy => "\"invalid_policy\""

def methodJson : RpcMethod -> String
  | RpcMethod.safeMethod => "\"system_health\""
  | RpcMethod.daSubmitCiphertexts => "\"da_submitCiphertexts\""
  | RpcMethod.daSubmitProofs => "\"da_submitProofs\""
  | RpcMethod.hegemonStartMining => "\"hegemon_startMining\""
  | RpcMethod.hegemonStopMining => "\"hegemon_stopMining\""
  | RpcMethod.hegemonSubmitAction => "\"hegemon_submitAction\""

def methodRejectionJson : Option RpcMethodReject -> String
  | none => "null"
  | some RpcMethodReject.unsafeMethodDisabled => "\"unsafe_method_disabled\""

def policyCaseJson
    (name rawString : String)
    (raw : RawRpcPolicy)
    (rpcExternal : Bool) : String :=
  let result := resolveRpcPolicy raw rpcExternal
  let expectedPolicy :=
    match result with
    | Except.ok policy => some (match policy with
      | RpcPolicy.safeOnly => "safe"
      | RpcPolicy.unsafeAllowed => "unsafe")
    | Except.error _ => none
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"raw\": \"" ++ rawString ++ "\",\n"
    ++ "      \"raw_tag\": " ++ rawPolicyTagJson raw ++ ",\n"
    ++ "      \"rpc_external\": " ++ boolJson rpcExternal ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (rpcPolicyAccepts raw rpcExternal) ++ ",\n"
    ++ "      \"expected_policy\": " ++ nullableStringJson expectedPolicy ++ ",\n"
    ++ "      \"expected_rejection\": " ++ policyRejectionJson result ++ "\n"
    ++ "    }"

def methodGateCaseJson
    (name : String)
    (policy : RpcPolicy)
    (method : RpcMethod) : String :=
  let result := evaluateRpcMethodGate policy method
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"policy\": " ++ policyJson policy ++ ",\n"
    ++ "      \"method\": " ++ methodJson method ++ ",\n"
    ++ "      \"is_unsafe_method\": " ++ boolJson (rpcMethodIsUnsafe method) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ methodRejectionJson result ++ "\n"
    ++ "    }"

def methodListCaseJson (name : String) (policy : RpcPolicy) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"policy\": " ++ policyJson policy ++ ",\n"
    ++ "      \"expected_unsafe_methods_visible\": "
      ++ boolJson (unsafeMethodsVisibleInList policy) ++ "\n"
    ++ "    }"

def timestampRejectionJson : Option TimestampRangeReject -> String
  | none => "null"
  | some TimestampRangeReject.endBeforeStart => "\"end_before_start\""
  | some TimestampRangeReject.rangeOverflow => "\"range_overflow\""
  | some TimestampRangeReject.rangeTooLarge => "\"range_too_large\""

def timestampCaseJson (name : String) (input : TimestampRangeInput) : String :=
  let result := evaluateTimestampRangeRejection input
  let requestedRows :=
    match timestampRangeRequestedRows input with
    | Except.ok rows => some (toString rows)
    | Except.error _ => none
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"start_height\": " ++ toString input.startHeight ++ ",\n"
    ++ "      \"end_height\": " ++ toString input.endHeight ++ ",\n"
    ++ "      \"max_rows\": " ++ toString input.maxRows ++ ",\n"
    ++ "      \"expected_requested_rows\": " ++ nullableStringJson requestedRows ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ timestampRejectionJson result ++ "\n"
    ++ "    }"

def encodingJson : ByteEncoding -> String
  | ByteEncoding.hex => "\"hex\""
  | ByteEncoding.base64 => "\"base64\""

def byteRejectionJson : Option ByteParseReject -> String
  | none => "null"
  | some ByteParseReject.hexTextTooLong => "\"hex_text_too_long\""
  | some ByteParseReject.base64TextTooLong => "\"base64_text_too_long\""
  | some ByteParseReject.decodedTooLong => "\"decoded_too_long\""

def byteCaseJson (name : String) (input : ByteParseInput) : String :=
  let result := evaluateByteParseRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"encoding\": " ++ encodingJson input.encoding ++ ",\n"
    ++ "      \"raw_text_bytes\": " ++ toString input.rawTextBytes ++ ",\n"
    ++ "      \"decoded_bytes\": " ++ toString input.decodedBytes ++ ",\n"
    ++ "      \"max_decoded_bytes\": " ++ toString input.maxDecodedBytes ++ ",\n"
    ++ "      \"expected_encoded_len_limit\": "
      ++ toString (encodedLenLimit input.maxDecodedBytes) ++ ",\n"
    ++ "      \"expected_hex_len_limit\": "
      ++ toString (hexLenLimit input.maxDecodedBytes) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ byteRejectionJson result ++ "\n"
    ++ "    }"

def batchRejectionJson : Option BatchReject -> String
  | none => "null"
  | some BatchReject.emptyBatch => "\"empty_batch\""
  | some BatchReject.batchTooLarge => "\"batch_too_large\""

def batchCaseJson (name : String) (input : BatchInput) : String :=
  let result := evaluateBatchRejection input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"request_count\": " ++ toString input.requestCount ++ ",\n"
    ++ "      \"max_requests\": " ++ toString input.maxRequests ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ batchRejectionJson result ++ "\n"
    ++ "    }"

def byteBase64Exact : ByteParseInput :=
  {
    encoding := ByteEncoding.base64,
    rawTextBytes := 8,
    decodedBytes := 4,
    maxDecodedBytes := 4
  }

def byteBase64TextOver : ByteParseInput :=
  {
    encoding := ByteEncoding.base64,
    rawTextBytes := encodedLenLimit 4 + 1,
    decodedBytes := 4,
    maxDecodedBytes := 4
  }

def byteBase64DecodedOver : ByteParseInput :=
  {
    encoding := ByteEncoding.base64,
    rawTextBytes := 8,
    decodedBytes := 5,
    maxDecodedBytes := 4
  }

def byteHexExact : ByteParseInput :=
  {
    encoding := ByteEncoding.hex,
    rawTextBytes := 8,
    decodedBytes := 4,
    maxDecodedBytes := 4
  }

def byteHexTextOver : ByteParseInput :=
  {
    encoding := ByteEncoding.hex,
    rawTextBytes := 10,
    decodedBytes := 5,
    maxDecodedBytes := 4
  }

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"policy_cases\": [\n"
    ++ policyCaseJson "safe-token" "safe" RawRpcPolicy.safeToken false ++ ",\n"
    ++ policyCaseJson "unsafe-token" "unsafe" RawRpcPolicy.unsafeToken false ++ ",\n"
    ++ policyCaseJson "external-auto-resolves-safe" "auto" RawRpcPolicy.autoToken true ++ ",\n"
    ++ policyCaseJson "local-auto-resolves-unsafe" "auto" RawRpcPolicy.autoToken false ++ ",\n"
    ++ policyCaseJson "external-empty-resolves-safe" "" RawRpcPolicy.emptyToken true ++ ",\n"
    ++ policyCaseJson "local-empty-resolves-unsafe" "" RawRpcPolicy.emptyToken false ++ ",\n"
    ++ policyCaseJson "trimmed-uppercase-safe" " SAFE " RawRpcPolicy.safeToken true ++ ",\n"
    ++ policyCaseJson "invalid-policy-rejected" "public" RawRpcPolicy.invalidToken false ++ "\n"
    ++ "  ],\n"
    ++ "  \"method_gate_cases\": [\n"
    ++ methodGateCaseJson "safe-method-under-safe-policy" RpcPolicy.safeOnly
      RpcMethod.safeMethod ++ ",\n"
    ++ methodGateCaseJson "unsafe-method-under-safe-policy" RpcPolicy.safeOnly
      RpcMethod.daSubmitCiphertexts ++ ",\n"
    ++ methodGateCaseJson "unsafe-method-under-unsafe-policy" RpcPolicy.unsafeAllowed
      RpcMethod.daSubmitCiphertexts ++ ",\n"
    ++ methodGateCaseJson "proof-upload-unsafe-under-safe-policy" RpcPolicy.safeOnly
      RpcMethod.daSubmitProofs ++ ",\n"
    ++ methodGateCaseJson "start-mining-unsafe-under-safe-policy" RpcPolicy.safeOnly
      RpcMethod.hegemonStartMining ++ ",\n"
    ++ methodGateCaseJson "stop-mining-unsafe-under-safe-policy" RpcPolicy.safeOnly
      RpcMethod.hegemonStopMining ++ ",\n"
    ++ methodGateCaseJson "submit-action-unsafe-under-safe-policy" RpcPolicy.safeOnly
      RpcMethod.hegemonSubmitAction ++ "\n"
    ++ "  ],\n"
    ++ "  \"method_list_cases\": [\n"
    ++ methodListCaseJson "safe-list-hides-unsafe-methods" RpcPolicy.safeOnly ++ ",\n"
    ++ methodListCaseJson "unsafe-list-shows-unsafe-methods" RpcPolicy.unsafeAllowed ++ "\n"
    ++ "  ],\n"
    ++ "  \"timestamp_range_cases\": [\n"
    ++ timestampCaseJson "timestamp-exact-limit" validTimestampRange ++ ",\n"
    ++ timestampCaseJson "timestamp-over-limit-rejected" overlargeTimestampRange ++ ",\n"
    ++ timestampCaseJson "timestamp-inverted-range-rejected" invertedTimestampRange ++ ",\n"
    ++ timestampCaseJson "timestamp-u64-overflow-rejected" overflowTimestampRange ++ "\n"
    ++ "  ],\n"
    ++ "  \"byte_parse_cases\": [\n"
    ++ byteCaseJson "base64-exact-limit" byteBase64Exact ++ ",\n"
    ++ byteCaseJson "base64-text-over-limit-rejected" byteBase64TextOver ++ ",\n"
    ++ byteCaseJson "base64-decoded-over-limit-rejected" byteBase64DecodedOver ++ ",\n"
    ++ byteCaseJson "hex-exact-limit" byteHexExact ++ ",\n"
    ++ byteCaseJson "hex-text-over-limit-rejected" byteHexTextOver ++ "\n"
    ++ "  ],\n"
    ++ "  \"batch_cases\": [\n"
    ++ batchCaseJson "batch-one-accepted"
      { requestCount := 1, maxRequests := maxRpcBatchRequests } ++ ",\n"
    ++ batchCaseJson "batch-exact-limit-accepted" validBatch ++ ",\n"
    ++ batchCaseJson "batch-empty-rejected" emptyBatch ++ ",\n"
    ++ batchCaseJson "batch-over-limit-rejected" overlargeBatch ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
