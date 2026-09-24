import Hegemon.Native.BlockBodyChunkTransportAdmission

open Hegemon.Native.BlockBodyChunkTransportAdmission

def boolJson (value : Bool) : String := if value then "true" else "false"

def optionNatJson : Option Nat -> String
  | none => "null"
  | some value => toString value

def optionBoolJson : Option Bool -> String
  | none => "null"
  | some value => boolJson value

def natListJson (values : List Nat) : String :=
  "[" ++ String.intercalate "," (values.map toString) ++ "]"

def locatorRejectLabel : LocatorReject -> String
  | .schemaVersion => "schema_version"
  | .chainId => "chain_id"
  | .rulesHash => "rules_hash"
  | .totalLenEmpty => "total_len_empty"
  | .totalLenTooLarge => "total_len_too_large"
  | .chunkCount => "chunk_count"

def locatorCaseJson (name : String) (input : LocatorInput) : String :=
  let result := evaluateLocator input
  let rejection := match result with
    | Except.ok _ => "null"
    | Except.error reject => "\"" ++ locatorRejectLabel reject ++ "\""
  let expectedCount := match result with
    | Except.ok count => some count
    | Except.error _ => none
  "    {\"name\":\"" ++ name ++ "\","
    ++ "\"schema_matches\":" ++ boolJson input.schemaMatches ++ ","
    ++ "\"chain_id_matches\":" ++ boolJson input.chainIdMatches ++ ","
    ++ "\"rules_hash_matches\":" ++ boolJson input.rulesHashMatches ++ ","
    ++ "\"total_len\":" ++ toString input.totalLen ++ ","
    ++ "\"declared_chunk_count\":" ++ toString input.declaredChunkCount ++ ","
    ++ "\"expected_chunk_count\":" ++ optionNatJson expectedCount ++ ","
    ++ "\"expected_rejection\":" ++ rejection ++ "}"

def chunkRejectLabel : ChunkReject -> String
  | .totalLenEmpty => "total_len_empty"
  | .totalLenTooLarge => "total_len_too_large"
  | .chunkCount => "chunk_count"
  | .chunkIndex => "chunk_index"
  | .payloadTooLarge => "payload_too_large"
  | .chunkLength => "chunk_length"

def chunkCaseJson (name : String) (input : ChunkInput) : String :=
  let result := evaluateChunk input
  let rejection := match result with
    | Except.ok _ => "null"
    | Except.error reject => "\"" ++ chunkRejectLabel reject ++ "\""
  let expectedLen := match result with
    | Except.ok length => some length
    | Except.error _ => none
  "    {\"name\":\"" ++ name ++ "\","
    ++ "\"total_len\":" ++ toString input.totalLen ++ ","
    ++ "\"declared_chunk_count\":" ++ toString input.declaredChunkCount ++ ","
    ++ "\"chunk_index\":" ++ toString input.chunkIndex ++ ","
    ++ "\"declared_chunk_len\":" ++ toString input.declaredChunkLen ++ ","
    ++ "\"actual_chunk_len\":" ++ toString input.actualChunkLen ++ ","
    ++ "\"expected_chunk_len\":" ++ optionNatJson expectedLen ++ ","
    ++ "\"expected_rejection\":" ++ rejection ++ "}"

def registrationRejectLabel : RegistrationReject -> String
  | .locator => "locator"
  | .conflictingLocator => "conflicting_locator"
  | .perPeerLimit => "per_peer_limit"
  | .globalLimit => "global_limit"
  | .reservedByteOverflow => "reserved_byte_overflow"
  | .reservedByteLimit => "reserved_byte_limit"

def registrationCaseJson (name : String) (input : RegistrationInput) : String :=
  let result := evaluateRegistration input
  let rejection := match result with
    | Except.ok _ => "null"
    | Except.error reject => "\"" ++ registrationRejectLabel reject ++ "\""
  let registered := match result with
    | Except.ok inserted => some inserted
    | Except.error _ => none
  "    {\"name\":\"" ++ name ++ "\","
    ++ "\"locator_valid\":" ++ boolJson input.locatorValid ++ ","
    ++ "\"existing_same\":" ++ boolJson input.existingSame ++ ","
    ++ "\"existing_conflict\":" ++ boolJson input.existingConflict ++ ","
    ++ "\"peer_entries\":" ++ toString input.peerEntries ++ ","
    ++ "\"global_entries\":" ++ toString input.globalEntries ++ ","
    ++ "\"reserved_bytes\":" ++ toString input.reservedBytes ++ ","
    ++ "\"incoming_total_len\":" ++ toString input.incomingTotalLen ++ ","
    ++ "\"expected_registered\":" ++ optionBoolJson registered ++ ","
    ++ "\"expected_rejection\":" ++ rejection ++ "}"

def pushRejectLabel : PushReject -> String
  | .chunk => "chunk"
  | .unsolicited => "unsolicited"
  | .locatorConflict => "locator_conflict"
  | .duplicate => "duplicate"
  | .conflictingDuplicate => "conflicting_duplicate"
  | .receivedByteOverflow => "received_byte_overflow"
  | .receivedBytesExceedTotal => "received_bytes_exceed_total"

def pushCaseJson (name : String) (input : PushInput) : String :=
  let result := evaluatePush input
  let rejection := match result with
    | Except.ok _ => "null"
    | Except.error reject => "\"" ++ pushRejectLabel reject ++ "\""
  let received := match result with
    | Except.ok count => some count
    | Except.error _ => none
  "    {\"name\":\"" ++ name ++ "\","
    ++ "\"chunk_valid\":" ++ boolJson input.chunkValid ++ ","
    ++ "\"requested\":" ++ boolJson input.requested ++ ","
    ++ "\"locator_matches\":" ++ boolJson input.locatorMatches ++ ","
    ++ "\"duplicate_present\":" ++ boolJson input.duplicatePresent ++ ","
    ++ "\"duplicate_bytes_match\":" ++ boolJson input.duplicateBytesMatch ++ ","
    ++ "\"received_bytes\":" ++ toString input.receivedBytes ++ ","
    ++ "\"incoming_bytes\":" ++ toString input.incomingBytes ++ ","
    ++ "\"declared_total_len\":" ++ toString input.declaredTotalLen ++ ","
    ++ "\"expected_received_bytes\":" ++ optionNatJson received ++ ","
    ++ "\"expected_rejection\":" ++ rejection ++ "}"

def completionRejectLabel : CompletionReject -> String
  | .receivedLength => "received_length"
  | .reassembledLength => "reassembled_length"
  | .bodyHash => "body_hash"
  | .bincodeBudget => "bincode_budget"
  | .exactDecode => "exact_decode"
  | .canonicalReencode => "canonical_reencode"
  | .locatorMetadata => "locator_metadata"

def completionCaseJson (name : String) (input : CompletionInput) : String :=
  let result := evaluateCompletion input
  let rejection := match result with
    | Except.ok _ => "null"
    | Except.error reject => "\"" ++ completionRejectLabel reject ++ "\""
  "    {\"name\":\"" ++ name ++ "\","
    ++ "\"received_length_matches\":" ++ boolJson input.receivedLengthMatches ++ ","
    ++ "\"reassembled_length_matches\":" ++ boolJson input.reassembledLengthMatches ++ ","
    ++ "\"body_hash_matches\":" ++ boolJson input.bodyHashMatches ++ ","
    ++ "\"bincode_budget_accepts\":" ++ boolJson input.bincodeBudgetAccepts ++ ","
    ++ "\"exact_decode_consumes_all\":" ++ boolJson input.exactDecodeConsumesAll ++ ","
    ++ "\"canonical_reencode_matches\":" ++ boolJson input.canonicalReencodeMatches ++ ","
    ++ "\"locator_metadata_matches\":" ++ boolJson input.locatorMetadataMatches ++ ","
    ++ "\"expected_rejection\":" ++ rejection ++ "}"

def joinCases (cases : List String) : String := String.intercalate ",\n" cases

def validLocator (totalLen : Nat) : LocatorInput :=
  {
    schemaMatches := true
    chainIdMatches := true
    rulesHashMatches := true
    totalLen := totalLen
    declaredChunkCount := derivedChunkCount totalLen
  }

def validCompletion : CompletionInput :=
  {
    receivedLengthMatches := true
    reassembledLengthMatches := true
    bodyHashMatches := true
    bincodeBudgetAccepts := true
    exactDecodeConsumesAll := true
    canonicalReencodeMatches := true
    locatorMetadataMatches := true
  }

def vectorJson : String :=
  let locatorCases := [
    locatorCaseJson "one-byte-body" (validLocator 1),
    locatorCaseJson "exact-one-chunk" (validLocator chunkBytes),
    locatorCaseJson "one-chunk-plus-one" (validLocator (chunkBytes + 1)),
    locatorCaseJson "maximum-body" (validLocator maxBodyBytes),
    locatorCaseJson "schema-rejected" { validLocator 1 with schemaMatches := false },
    locatorCaseJson "chain-rejected" { validLocator 1 with chainIdMatches := false },
    locatorCaseJson "rules-rejected" { validLocator 1 with rulesHashMatches := false },
    locatorCaseJson "empty-rejected"
      { validLocator 1 with
        totalLen := 0
        declaredChunkCount := 0
      },
    locatorCaseJson "maximum-plus-one-rejected"
      { validLocator 1 with
        totalLen := maxBodyBytes + 1
        declaredChunkCount := maxChunkCount + 1
      },
    locatorCaseJson "count-mismatch-rejected"
      { validLocator (chunkBytes + 1) with declaredChunkCount := 1 },
    locatorCaseJson "schema-precedes-all"
      {
        schemaMatches := false
        chainIdMatches := false
        rulesHashMatches := false
        totalLen := 0
        declaredChunkCount := 0
      }
  ]
  let chunkCases := [
    chunkCaseJson "one-byte-chunk"
      {
        totalLen := 1
        declaredChunkCount := 1
        chunkIndex := 0
        declaredChunkLen := 1
        actualChunkLen := 1
      },
    chunkCaseJson "exact-full-chunk"
      {
        totalLen := chunkBytes
        declaredChunkCount := 1
        chunkIndex := 0
        declaredChunkLen := chunkBytes
        actualChunkLen := chunkBytes
      },
    chunkCaseJson "exact-final-remainder"
      {
        totalLen := chunkBytes + 17
        declaredChunkCount := 2
        chunkIndex := 1
        declaredChunkLen := 17
        actualChunkLen := 17
      },
    chunkCaseJson "empty-total-rejected"
      {
        totalLen := 0
        declaredChunkCount := 0
        chunkIndex := 0
        declaredChunkLen := 0
        actualChunkLen := 0
      },
    chunkCaseJson "oversized-total-rejected"
      {
        totalLen := maxBodyBytes + 1
        declaredChunkCount := maxChunkCount + 1
        chunkIndex := 0
        declaredChunkLen := chunkBytes
        actualChunkLen := chunkBytes
      },
    chunkCaseJson "count-mismatch-precedes-index"
      {
        totalLen := chunkBytes + 1
        declaredChunkCount := 1
        chunkIndex := 2
        declaredChunkLen := 0
        actualChunkLen := chunkBytes + 1
      },
    chunkCaseJson "index-rejected"
      {
        totalLen := chunkBytes + 1
        declaredChunkCount := 2
        chunkIndex := 2
        declaredChunkLen := 0
        actualChunkLen := 0
      },
    chunkCaseJson "payload-over-cap-rejected"
      {
        totalLen := chunkBytes + 1
        declaredChunkCount := 2
        chunkIndex := 0
        declaredChunkLen := chunkBytes
        actualChunkLen := chunkBytes + 1
      },
    chunkCaseJson "declared-length-mismatch-rejected"
      {
        totalLen := chunkBytes + 17
        declaredChunkCount := 2
        chunkIndex := 1
        declaredChunkLen := 16
        actualChunkLen := 17
      },
    chunkCaseJson "actual-length-mismatch-rejected"
      {
        totalLen := chunkBytes + 17
        declaredChunkCount := 2
        chunkIndex := 1
        declaredChunkLen := 17
        actualChunkLen := 16
      }
  ]
  let registrationCases := [
    registrationCaseJson "new-registration"
      {
        locatorValid := true
        existingSame := false
        existingConflict := false
        peerEntries := 0
        globalEntries := 0
        reservedBytes := 0
        incomingTotalLen := 1
      },
    registrationCaseJson "identical-registration-idempotent"
      {
        locatorValid := true
        existingSame := true
        existingConflict := false
        peerEntries := 1
        globalEntries := 4
        reservedBytes := maxReservedBytes
        incomingTotalLen := 1
      },
    registrationCaseJson "conflicting-locator-rejected"
      {
        locatorValid := true
        existingSame := false
        existingConflict := true
        peerEntries := 0
        globalEntries := 0
        reservedBytes := 0
        incomingTotalLen := 1
      },
    registrationCaseJson "per-peer-limit-rejected"
      {
        locatorValid := true
        existingSame := false
        existingConflict := false
        peerEntries := 1
        globalEntries := 1
        reservedBytes := 1
        incomingTotalLen := 1
      },
    registrationCaseJson "global-limit-rejected"
      {
        locatorValid := true
        existingSame := false
        existingConflict := false
        peerEntries := 0
        globalEntries := 4
        reservedBytes := 4
        incomingTotalLen := 1
      },
    registrationCaseJson "exact-reserved-limit-accepted"
      {
        locatorValid := true
        existingSame := false
        existingConflict := false
        peerEntries := 0
        globalEntries := 3
        reservedBytes := maxReservedBytes - maxBodyBytes
        incomingTotalLen := maxBodyBytes
      },
    registrationCaseJson "reserved-limit-rejected"
      {
        locatorValid := true
        existingSame := false
        existingConflict := false
        peerEntries := 0
        globalEntries := 3
        reservedBytes := maxReservedBytes
        incomingTotalLen := 1
      },
    registrationCaseJson "reserved-overflow-rejected"
      {
        locatorValid := true
        existingSame := false
        existingConflict := false
        peerEntries := 0
        globalEntries := 0
        reservedBytes := usizeMax
        incomingTotalLen := 1
      },
    registrationCaseJson "invalid-locator-precedes-existing"
      {
        locatorValid := false
        existingSame := true
        existingConflict := true
        peerEntries := 1
        globalEntries := 4
        reservedBytes := usizeMax
        incomingTotalLen := 1
      }
  ]
  let pushCases := [
    pushCaseJson "requested-chunk-accepted"
      {
        chunkValid := true
        requested := true
        locatorMatches := true
        duplicatePresent := false
        duplicateBytesMatch := false
        receivedBytes := 0
        incomingBytes := 17
        declaredTotalLen := 17
      },
    pushCaseJson "invalid-chunk-precedes-request"
      {
        chunkValid := false
        requested := false
        locatorMatches := false
        duplicatePresent := true
        duplicateBytesMatch := false
        receivedBytes := usizeMax
        incomingBytes := 1
        declaredTotalLen := 0
      },
    pushCaseJson "unsolicited-rejected"
      {
        chunkValid := true
        requested := false
        locatorMatches := true
        duplicatePresent := false
        duplicateBytesMatch := false
        receivedBytes := 0
        incomingBytes := 1
        declaredTotalLen := 1
      },
    pushCaseJson "locator-conflict-rejected"
      {
        chunkValid := true
        requested := true
        locatorMatches := false
        duplicatePresent := false
        duplicateBytesMatch := false
        receivedBytes := 0
        incomingBytes := 1
        declaredTotalLen := 1
      },
    pushCaseJson "duplicate-rejected"
      {
        chunkValid := true
        requested := true
        locatorMatches := true
        duplicatePresent := true
        duplicateBytesMatch := true
        receivedBytes := 1
        incomingBytes := 1
        declaredTotalLen := 2
      },
    pushCaseJson "conflicting-duplicate-rejected"
      {
        chunkValid := true
        requested := true
        locatorMatches := true
        duplicatePresent := true
        duplicateBytesMatch := false
        receivedBytes := 1
        incomingBytes := 1
        declaredTotalLen := 2
      },
    pushCaseJson "received-overflow-rejected"
      {
        chunkValid := true
        requested := true
        locatorMatches := true
        duplicatePresent := false
        duplicateBytesMatch := false
        receivedBytes := usizeMax
        incomingBytes := 1
        declaredTotalLen := usizeMax
      },
    pushCaseJson "received-over-total-rejected"
      {
        chunkValid := true
        requested := true
        locatorMatches := true
        duplicatePresent := false
        duplicateBytesMatch := false
        receivedBytes := 1
        incomingBytes := 1
        declaredTotalLen := 1
      }
  ]
  let completionCases := [
    completionCaseJson "complete-body-accepted" validCompletion,
    completionCaseJson "received-length-rejected"
      { validCompletion with receivedLengthMatches := false },
    completionCaseJson "reassembled-length-rejected"
      { validCompletion with reassembledLengthMatches := false },
    completionCaseJson "body-hash-rejected" { validCompletion with bodyHashMatches := false },
    completionCaseJson "bincode-budget-rejected"
      { validCompletion with bincodeBudgetAccepts := false },
    completionCaseJson "trailing-or-decode-rejected"
      { validCompletion with exactDecodeConsumesAll := false },
    completionCaseJson "noncanonical-reencode-rejected"
      { validCompletion with canonicalReencodeMatches := false },
    completionCaseJson "locator-metadata-rejected"
      { validCompletion with locatorMetadataMatches := false },
    completionCaseJson "hash-precedes-decode"
      {
        receivedLengthMatches := true
        reassembledLengthMatches := true
        bodyHashMatches := false
        bincodeBudgetAccepts := false
        exactDecodeConsumesAll := false
        canonicalReencodeMatches := false
        locatorMetadataMatches := false
      }
  ]
  "{\n"
    ++ "  \"schema_version\": 1,\n"
    ++ "  \"constants\": {\"body_schema_version\":" ++ toString bodySchemaVersion
    ++ ",\"chunk_bytes\":" ++ toString chunkBytes
    ++ ",\"max_body_bytes\":" ++ toString maxBodyBytes
    ++ ",\"max_chunk_count\":" ++ toString maxChunkCount
    ++ ",\"max_reassemblies_per_peer\":" ++ toString maxReassembliesPerPeer
    ++ ",\"max_reassemblies_global\":" ++ toString maxReassembliesGlobal
    ++ ",\"max_reserved_bytes\":" ++ toString maxReservedBytes
    ++ ",\"body_hash_domain_bytes\":" ++ natListJson bodyHashDomain
    ++ ",\"sample_body_bytes\":[1,2,3],\"sample_hash_preimage_bytes\":"
    ++ natListJson (bodyHashPreimage [1, 2, 3]) ++ "},\n"
    ++ "  \"locator_cases\": [\n" ++ joinCases locatorCases ++ "\n  ],\n"
    ++ "  \"chunk_cases\": [\n" ++ joinCases chunkCases ++ "\n  ],\n"
    ++ "  \"registration_cases\": [\n" ++ joinCases registrationCases ++ "\n  ],\n"
    ++ "  \"push_cases\": [\n" ++ joinCases pushCases ++ "\n  ],\n"
    ++ "  \"completion_cases\": [\n" ++ joinCases completionCases ++ "\n  ]\n"
    ++ "}"

def main : IO Unit := IO.println vectorJson
