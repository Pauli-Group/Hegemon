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
  | RpcPolicy.poolOnly => "\"pool\""
  | RpcPolicy.publicSubmit => "\"public-submit\""
  | RpcPolicy.unsafeAllowed => "\"unsafe\""

def rawPolicyTagJson : RawRpcPolicy -> String
  | RawRpcPolicy.safeToken => "\"safe\""
  | RawRpcPolicy.poolToken => "\"pool\""
  | RawRpcPolicy.publicSubmitToken => "\"public-submit\""
  | RawRpcPolicy.unsafeToken => "\"unsafe\""
  | RawRpcPolicy.autoToken => "\"auto\""
  | RawRpcPolicy.emptyToken => "\"empty\""
  | RawRpcPolicy.invalidToken => "\"invalid\""

def policyRejectionJson : Except RpcPolicyReject RpcPolicy -> String
  | Except.ok _ => "null"
  | Except.error RpcPolicyReject.externalPoolPolicy => "\"external_pool_policy\""
  | Except.error RpcPolicyReject.invalidPolicy => "\"invalid_policy\""
  | Except.error RpcPolicyReject.externalUnsafePolicy => "\"external_unsafe_policy\""

def methodJson : RpcMethod -> String
  | RpcMethod.safeMethod => "\"system_health\""
  | RpcMethod.daSubmitCiphertexts => "\"da_submitCiphertexts\""
  | RpcMethod.daSubmitProofs => "\"da_submitProofs\""
  | RpcMethod.hegemonExportBridgeWitness => "\"hegemon_exportBridgeWitness\""
  | RpcMethod.hegemonPeerGraph => "\"hegemon_peerGraph\""
  | RpcMethod.hegemonPeerList => "\"hegemon_peerList\""
  | RpcMethod.hegemonStartMining => "\"hegemon_startMining\""
  | RpcMethod.hegemonStopMining => "\"hegemon_stopMining\""
  | RpcMethod.hegemonSubmitAction => "\"hegemon_submitAction\""
  | RpcMethod.systemPeers => "\"system_peers\""
  | RpcMethod.safeNonPoolMethod => "\"hegemon_latestBlock\""
  | RpcMethod.poolWork => "\"hegemon_poolWork\""
  | RpcMethod.compactJob => "\"hegemon_compactJob\""
  | RpcMethod.submitPoolShare => "\"hegemon_submitPoolShare\""
  | RpcMethod.submitCompactSolution => "\"hegemon_submitCompactSolution\""
  | RpcMethod.pendingActionChunk => "\"hegemon_pendingActionChunk\""
  | RpcMethod.developmentPendingActionChunk => "\"hegemon_developmentPendingActionChunk\""
  | RpcMethod.assetSnapshot => "\"hegemon_assetSnapshot\""
  | RpcMethod.assetRecoverySnapshot => "\"hegemon_assetRecoverySnapshot\""
  | RpcMethod.disabledProofService => "\"hegemon_generateProof\""
  | RpcMethod.unknownMethod => "\"unknown_public_rpc_method\""

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
      | RpcPolicy.poolOnly => "pool"
      | RpcPolicy.publicSubmit => "public-submit"
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

def allPolicies : List RpcPolicy := [.safeOnly, .poolOnly, .unsafeAllowed, .publicSubmit]

def allMethods : List RpcMethod :=
  [.safeMethod, .safeNonPoolMethod, .daSubmitCiphertexts, .daSubmitProofs,
   .hegemonExportBridgeWitness, .hegemonPeerGraph, .hegemonPeerList,
   .hegemonStartMining, .hegemonStopMining, .hegemonSubmitAction, .systemPeers,
   .poolWork, .compactJob, .submitPoolShare, .submitCompactSolution,
   .pendingActionChunk, .developmentPendingActionChunk, .assetSnapshot,
   .assetRecoverySnapshot, .disabledProofService, .unknownMethod]

def caseName (casePrefix : String) (policy : RpcPolicy) (method : RpcMethod)
    (featureEnabled available : Bool) : String :=
  casePrefix ++ "-" ++ reprStr policy ++ "-" ++ reprStr method ++ "-" ++
    toString featureEnabled ++ "-" ++ toString available

def methodGateCaseJson (policy : RpcPolicy) (method : RpcMethod)
    (featureEnabled : Bool) : String :=
  let allowed := rpcMethodAllowedWithFeatures policy method featureEnabled
  "    {\n"
    ++ "      \"name\": \"" ++ caseName "gate" policy method featureEnabled true ++ "\",\n"
    ++ "      \"policy\": " ++ policyJson policy ++ ",\n"
    ++ "      \"method\": " ++ methodJson method ++ ",\n"
    ++ "      \"feature_enabled\": " ++ boolJson featureEnabled ++ ",\n"
    ++ "      \"is_unsafe_method\": " ++ boolJson (rpcMethodIsUnsafeWithFeatures method featureEnabled) ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson allowed ++ ",\n"
    ++ "      \"expected_rejection\": " ++
      nullableStringJson (if allowed then none else some "unsafe_method_disabled") ++ "\n"
    ++ "    }"

def methodListCaseJson (policy : RpcPolicy) (method : RpcMethod)
    (featureEnabled available : Bool) : String :=
  "    {\n"
    ++ "      \"name\": \"" ++ caseName "dispatch" policy method featureEnabled available ++ "\",\n"
    ++ "      \"policy\": " ++ policyJson policy ++ ",\n"
    ++ "      \"method\": " ++ methodJson method ++ ",\n"
    ++ "      \"feature_enabled\": " ++ boolJson featureEnabled ++ ",\n"
    ++ "      \"available\": " ++ boolJson available ++ ",\n"
    ++ "      \"expected_registered\": " ++ boolJson (rpcMethodRegistered method featureEnabled) ++ ",\n"
    ++ "      \"expected_visible\": " ++ boolJson (rpcMethodListed policy method featureEnabled available) ++ "\n"
    ++ "    }"

def methodGateCases : List String :=
  allPolicies.flatMap fun p => allMethods.flatMap fun m =>
    [false, true].map fun f => methodGateCaseJson p m f

def methodListCases : List String :=
  allPolicies.flatMap fun p => allMethods.flatMap fun m =>
    [false, true].flatMap fun f => [false, true].map fun a => methodListCaseJson p m f a

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

def nullableNatJson : Option Nat -> String
  | none => "null"
  | some n => toString n

def resourceCaseJson (kind : String) (first second : Nat) (flag : Bool)
    (expectedCount : Option Nat) (expectedBool : Bool) : String :=
  "    {\"kind\": \"" ++ kind ++ "\", \"first\": " ++ toString first ++
  ", \"second\": " ++ toString second ++ ", \"flag\": " ++ boolJson flag ++
  ", \"expected_count\": " ++ nullableNatJson expectedCount ++
  ", \"expected_bool\": " ++ boolJson expectedBool ++ "}"

def resourceCases : List String :=
  ([0, 1, 2, 65535].flatMap fun family =>
    [0, 1, 8, 14, 15, 16, 65535].map fun action =>
      resourceCaseJson "route" family action false none (publicSubmitActionRouteAllowed family action)) ++
  ([0, 1, 2, 3, 6, 1024, u64Max].flatMap fun active =>
    [0, 1, 2, 4, 6, 1024, u64Max].map fun limit =>
      resourceCaseJson "reserve" active limit false (publicCapacityReserve active limit) false) ++
  ([0, 1, 2, 4, 1024, u64Max].map fun active =>
      resourceCaseJson "release" active 0 false (publicCapacityRelease active) false) ++
  ([0, 1, 5, 6, 7, 4294967295].flatMap fun used =>
    [0, 1, 6, 60, 4294967295].flatMap fun limit => [false, true].map fun expired =>
      resourceCaseJson "charge" used limit expired (publicClientCharge used limit expired) false) ++
  ([0, 1, 2, 1024, u64Max].flatMap fun retained =>
    [0, 1, 1024, u64Max].flatMap fun capacity => [false, true].map fun known =>
      resourceCaseJson "table" retained capacity known none
        (publicClientTableInsertAllowed retained capacity known))

def ownershipCaseJson (kind : String) (submission : Bool) (states : List OwnedReservation) : String :=
  "    {\"kind\": \"" ++ kind ++ "\", \"expected_active\": [" ++
    String.intercalate "," (states.map fun state => toString state.active) ++
    "], \"expected_submissions\": [" ++ String.intercalate ","
      (states.map fun state => toString (if submission then state.active else 0)) ++ "]}"

def ownershipCases : List String :=
  let caller : OwnedReservation := { owner := .caller, active := 1 }
  let worker := moveReservationToWorker caller
  let cancelled := disconnectCaller worker
  let response := moveReservationToResponse worker
  [ownershipCaseJson "worker_cancel" true [caller, worker, cancelled, dropReservation worker],
   ownershipCaseJson "worker_failure" true [caller, worker, cancelled, dropReservation worker],
   ownershipCaseJson "response_drop" false [caller, worker, response, response, dropReservation response],
   ownershipCaseJson "response_exhaust" false [caller, worker, response, response, dropReservation response]]

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 2,\n"
    ++ "  \"policy_cases\": [\n"
    ++ policyCaseJson "safe-token" "safe" RawRpcPolicy.safeToken false ++ ",\n"
    ++ policyCaseJson "local-pool" "pool" RawRpcPolicy.poolToken false ++ ",\n"
    ++ policyCaseJson "external-pool-rejected" "pool" RawRpcPolicy.poolToken true ++ ",\n"
    ++ policyCaseJson "local-public-submit" "public-submit" RawRpcPolicy.publicSubmitToken false ++ ",\n"
    ++ policyCaseJson "external-public-submit" "public-submit" RawRpcPolicy.publicSubmitToken true ++ ",\n"
    ++ policyCaseJson "trimmed-public-submit" " PUBLIC-SUBMIT " RawRpcPolicy.publicSubmitToken true ++ ",\n"
    ++ policyCaseJson "unsafe-token" "unsafe" RawRpcPolicy.unsafeToken false ++ ",\n"
    ++ policyCaseJson "external-unsafe-rejected" "unsafe" RawRpcPolicy.unsafeToken true ++ ",\n"
    ++ policyCaseJson "external-auto-resolves-safe" "auto" RawRpcPolicy.autoToken true ++ ",\n"
    ++ policyCaseJson "local-auto-resolves-safe" "auto" RawRpcPolicy.autoToken false ++ ",\n"
    ++ policyCaseJson "external-empty-resolves-safe" "" RawRpcPolicy.emptyToken true ++ ",\n"
    ++ policyCaseJson "local-empty-resolves-safe" "" RawRpcPolicy.emptyToken false ++ ",\n"
    ++ policyCaseJson "trimmed-uppercase-safe" " SAFE " RawRpcPolicy.safeToken true ++ ",\n"
    ++ policyCaseJson "invalid-policy-rejected" "public" RawRpcPolicy.invalidToken false ++ "\n"
    ++ "  ],\n"
    ++ "  \"method_gate_cases\": [\n"
    ++ String.intercalate ",\n" methodGateCases ++ "\n  ],\n"
    ++ "  \"method_list_cases\": [\n"
    ++ String.intercalate ",\n" methodListCases ++ "\n  ],\n"
    ++ "  \"ownership_cases\": [\n"
    ++ String.intercalate ",\n" ownershipCases ++ "\n  ],\n"
    ++ "  \"resource_cases\": [\n"
    ++ String.intercalate ",\n" resourceCases ++ "\n  ],\n"
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
