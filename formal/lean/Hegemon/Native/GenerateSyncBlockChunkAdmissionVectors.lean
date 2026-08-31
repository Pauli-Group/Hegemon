import Hegemon.Native.SyncBlockChunkAdmission

open Hegemon.Native.SyncBlockChunkAdmission

def boolJson (value : Bool) : String :=
  if value then "true" else "false"

def rejectionJson : Option SyncBlockChunkReject -> String
  | none => "null"
  | some .noMatchingRequest => "\"no_matching_request\""
  | some .noMatchingOffer => "\"no_matching_offer\""
  | some .responseNotEmpty => "\"response_not_empty\""
  | some .peerBestBelowRequested => "\"peer_best_below_requested\""
  | some .sessionCapacity => "\"session_capacity\""
  | some .sessionExpired => "\"session_expired\""
  | some .sessionMismatch => "\"session_mismatch\""
  | some .invalidOutboundTransition => "\"invalid_outbound_transition\""
  | some .emptyChunk => "\"empty_chunk\""
  | some .chunkTooLarge => "\"chunk_too_large\""
  | some .chunkLengthMismatch => "\"chunk_length_mismatch\""
  | some .totalLenInvalid => "\"total_len_invalid\""
  | some .offsetMismatch => "\"offset_mismatch\""
  | some .chunkEndOverflow => "\"chunk_end_overflow\""
  | some .chunkEndPastTotal => "\"chunk_end_past_total\""
  | some .completeLengthMismatch => "\"complete_length_mismatch\""
  | some .recordDigestMismatch => "\"record_digest_mismatch\""
  | some .recordDecodeRejected => "\"record_decode_rejected\""
  | some .recordHeightMismatch => "\"record_height_mismatch\""
  | some .recordHashMismatch => "\"record_hash_mismatch\""
  | some .requestPrefixMismatch => "\"request_prefix_mismatch\""
  | some .recoveryContextMismatch => "\"recovery_context_mismatch\""

def tipRejectionJson : Option SyncTipAnnouncementReject -> String
  | none => "null"
  | some .notAhead => "\"not_ahead\""
  | some .zeroHash => "\"zero_hash\""

def fallbackCaseJson
    (name : String)
    (input : SyncChunkFallbackAdmissionInput) : String :=
  let result := evaluateSyncChunkFallbackAdmission input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"matching_completed_request\": "
      ++ boolJson input.matchingCompletedRequest ++ ",\n"
    ++ "      \"response_empty\": " ++ boolJson input.responseEmpty ++ ",\n"
    ++ "      \"peer_best_height\": " ++ toString input.peerBestHeight ++ ",\n"
    ++ "      \"requested_from_height\": "
      ++ toString input.requestedFromHeight ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def capacityCaseJson
    (name : String)
    (input : SyncChunkSessionCapacityInput) : String :=
  let result := evaluateSyncChunkSessionCapacity input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"current_sessions\": " ++ toString input.currentSessions ++ ",\n"
    ++ "      \"max_sessions\": " ++ toString input.maxSessions ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def serveDispositionJson : Option SyncChunkServeRequestDisposition -> String
  | none => "null"
  | some .serveNext => "\"serve_next\""
  | some .close => "\"close\""

def serveRequestCaseJson
    (name : String)
    (input : SyncChunkServeRequestAdmissionInput) : String :=
  let result := evaluateSyncChunkServeRequestAdmission input
  let disposition := match result with
    | .ok value => some value
    | .error _ => none
  let rejection := match result with
    | .ok _ => none
    | .error value => some value
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"matching_live_offer_or_session\": "
      ++ boolJson input.matchingLiveOfferOrSession ++ ",\n"
    ++ "      \"tuple_matches\": " ++ boolJson input.tupleMatches ++ ",\n"
    ++ "      \"offset\": " ++ toString input.offset ++ ",\n"
    ++ "      \"next_offset\": " ++ toString input.nextOffset ++ ",\n"
    ++ "      \"total_len\": " ++ toString input.totalLen ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson result.isOk ++ ",\n"
    ++ "      \"expected_disposition\": "
      ++ serveDispositionJson disposition ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson rejection ++ "\n"
    ++ "    }"

def offerRequestCaseJson
    (name : String)
    (input : SyncChunkOfferRequestAdmissionInput) : String :=
  let result := evaluateSyncChunkOfferRequestAdmission input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"matching_live_offer\": "
      ++ boolJson input.matchingLiveOffer ++ ",\n"
    ++ "      \"height_matches\": " ++ boolJson input.heightMatches ++ ",\n"
    ++ "      \"block_hash_matches\": "
      ++ boolJson input.blockHashMatches ++ ",\n"
    ++ "      \"record_digest_absent\": "
      ++ boolJson input.recordDigestAbsent ++ ",\n"
    ++ "      \"offset\": " ++ toString input.offset ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def outboundStateJson : Option SyncChunkOutboundState -> String
  | none => "null"
  | some .inFlight => "\"in_flight\""
  | some .chunkFallback => "\"chunk_fallback\""
  | some .cooldown => "\"cooldown\""
  | some .absent => "\"absent\""

def outboundEventJson : SyncChunkOutboundEvent -> String
  | .admittedEmptyResponse => "\"admitted_empty_response\""
  | .complete => "\"complete\""
  | .abort => "\"abort\""

def outboundTransitionCaseJson
    (name : String)
    (input : SyncChunkOutboundTransitionInput) : String :=
  let result := evaluateSyncChunkOutboundTransition input
  let state := match result with
    | .ok value => some value
    | .error _ => none
  let rejection := match result with
    | .ok _ => none
    | .error value => some value
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"state\": " ++ outboundStateJson (some input.state) ++ ",\n"
    ++ "      \"event\": " ++ outboundEventJson input.event ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson result.isOk ++ ",\n"
    ++ "      \"expected_state\": " ++ outboundStateJson state ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson rejection ++ "\n"
    ++ "    }"

def expiryCaseJson
    (name : String)
    (input : SyncChunkSessionExpiryInput) : String :=
  let result := evaluateSyncChunkSessionExpiry input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"idle_elapsed_ms\": " ++ toString input.idleElapsedMs ++ ",\n"
    ++ "      \"max_idle_ms\": " ++ toString input.maxIdleMs ++ ",\n"
    ++ "      \"lifetime_elapsed_ms\": "
      ++ toString input.lifetimeElapsedMs ++ ",\n"
    ++ "      \"max_lifetime_ms\": " ++ toString input.maxLifetimeMs ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def tipCaseJson
    (name : String)
    (input : SyncTipAnnouncementAdmissionInput) : String :=
  let result := evaluateSyncTipAnnouncementAdmission input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"local_height\": " ++ toString input.localHeight ++ ",\n"
    ++ "      \"announced_height\": " ++ toString input.announcedHeight ++ ",\n"
    ++ "      \"announced_hash_is_zero\": "
      ++ boolJson input.announcedHashIsZero ++ ",\n"
    ++ "      \"announced_hash_matches_local\": "
      ++ boolJson input.announcedHashMatchesLocal ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ tipRejectionJson result ++ "\n"
    ++ "    }"

def chunkCaseJson
    (name : String)
    (input : SyncBlockChunkAdmissionInput) : String :=
  let result := evaluateSyncBlockChunkAdmission input
  let resource := syncBlockChunkResourceRequest input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"session_matches\": " ++ boolJson input.sessionMatches ++ ",\n"
    ++ "      \"chunk_bytes\": " ++ toString input.chunkBytes ++ ",\n"
    ++ "      \"max_chunk_bytes\": " ++ toString input.maxChunkBytes ++ ",\n"
    ++ "      \"total_bytes\": " ++ toString input.totalBytes ++ ",\n"
    ++ "      \"max_total_bytes\": " ++ toString input.maxTotalBytes ++ ",\n"
    ++ "      \"offset\": " ++ toString input.offset ++ ",\n"
    ++ "      \"retained_bytes\": " ++ toString input.retainedBytes ++ ",\n"
    ++ "      \"expected_retained_after\": "
      ++ toString resource.aggregateBytes ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def completionCaseJson
    (name : String)
    (input : SyncBlockChunkCompletionAdmissionInput) : String :=
  let result := evaluateSyncBlockChunkCompletionAdmission input
  "    {\n"
    ++ "      \"name\": \"" ++ name ++ "\",\n"
    ++ "      \"assembled_bytes\": " ++ toString input.assembledBytes ++ ",\n"
    ++ "      \"total_bytes\": " ++ toString input.totalBytes ++ ",\n"
    ++ "      \"digest_matches\": " ++ boolJson input.digestMatches ++ ",\n"
    ++ "      \"exact_decode_accepts\": "
      ++ boolJson input.exactDecodeAccepts ++ ",\n"
    ++ "      \"height_matches\": " ++ boolJson input.heightMatches ++ ",\n"
    ++ "      \"hash_matches\": " ++ boolJson input.hashMatches ++ ",\n"
    ++ "      \"request_prefix_matches\": "
      ++ boolJson input.requestPrefixMatches ++ ",\n"
    ++ "      \"recovery_context_matches\": "
      ++ boolJson input.recoveryContextMatches ++ ",\n"
    ++ "      \"expected_valid\": " ++ boolJson (result == none) ++ ",\n"
    ++ "      \"expected_rejection\": " ++ rejectionJson result ++ "\n"
    ++ "    }"

def vectorJson : String :=
  "{\n"
    ++ "  \"schema_version\": 4,\n"
    ++ "  \"sync_chunk_fallback_cases\": [\n"
    ++ fallbackCaseJson "valid-matching-empty-response" validFallback ++ ",\n"
    ++ fallbackCaseJson "fallback-no-matching-request"
      { validFallback with matchingCompletedRequest := false } ++ ",\n"
    ++ fallbackCaseJson "fallback-response-not-empty"
      { validFallback with responseEmpty := false } ++ ",\n"
    ++ fallbackCaseJson "fallback-peer-best-below-requested"
      { validFallback with peerBestHeight := 99 } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_chunk_capacity_cases\": [\n"
    ++ capacityCaseJson "capacity-below-limit" validCapacity ++ ",\n"
    ++ capacityCaseJson "capacity-exact-limit"
      { validCapacity with currentSessions := 2 } ++ ",\n"
    ++ capacityCaseJson "capacity-zero-limit"
      { validCapacity with currentSessions := 0, maxSessions := 0 } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_chunk_serve_request_cases\": [\n"
    ++ serveRequestCaseJson "serve-matching-next-offset" validServeRequest ++ ",\n"
    ++ serveRequestCaseJson "serve-no-matching-offer"
      { validServeRequest with matchingLiveOfferOrSession := false } ++ ",\n"
    ++ serveRequestCaseJson "serve-tuple-mismatch"
      { validServeRequest with tupleMatches := false } ++ ",\n"
    ++ serveRequestCaseJson "serve-offset-mismatch"
      { validServeRequest with offset := 3 } ++ ",\n"
    ++ serveRequestCaseJson "serve-close-ack"
      { validServeRequest with offset := 8 } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_chunk_offer_request_cases\": [\n"
    ++ offerRequestCaseJson "offer-initial-offset-zero" validOfferRequest ++ ",\n"
    ++ offerRequestCaseJson "offer-no-matching-live-offer"
      { validOfferRequest with matchingLiveOffer := false } ++ ",\n"
    ++ offerRequestCaseJson "offer-height-mismatch"
      { validOfferRequest with heightMatches := false } ++ ",\n"
    ++ offerRequestCaseJson "offer-block-hash-mismatch"
      { validOfferRequest with blockHashMatches := false } ++ ",\n"
    ++ offerRequestCaseJson "offer-record-digest-present"
      { validOfferRequest with recordDigestAbsent := false } ++ ",\n"
    ++ offerRequestCaseJson "offer-nonzero-offset"
      { validOfferRequest with offset := 1 } ++ ",\n"
    ++ offerRequestCaseJson "offer-u64-max-offset"
      { validOfferRequest with offset := u64Max } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_chunk_outbound_transition_cases\": [\n"
    ++ outboundTransitionCaseJson "transition-empty-response-to-fallback" {
      state := .inFlight,
      event := .admittedEmptyResponse
    } ++ ",\n"
    ++ outboundTransitionCaseJson "transition-complete-removes-request" {
      state := .chunkFallback,
      event := .complete
    } ++ ",\n"
    ++ outboundTransitionCaseJson "transition-abort-to-cooldown" {
      state := .chunkFallback,
      event := .abort
    } ++ ",\n"
    ++ outboundTransitionCaseJson "transition-duplicate-empty-response-rejected" {
      state := .chunkFallback,
      event := .admittedEmptyResponse
    } ++ ",\n"
    ++ outboundTransitionCaseJson "transition-inflight-complete-rejected" {
      state := .inFlight,
      event := .complete
    } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_chunk_expiry_cases\": [\n"
    ++ expiryCaseJson "session-live" validExpiry ++ ",\n"
    ++ expiryCaseJson "session-idle-exact-limit-expired"
      { validExpiry with idleElapsedMs := 30000 } ++ ",\n"
    ++ expiryCaseJson "session-lifetime-exact-limit-expired"
      { validExpiry with lifetimeElapsedMs := 120000 } ++ ",\n"
    ++ expiryCaseJson "session-zero-limits-expired"
      { validExpiry with
        idleElapsedMs := 0,
        maxIdleMs := 0,
        lifetimeElapsedMs := 0,
        maxLifetimeMs := 0 } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_tip_announcement_cases\": [\n"
    ++ tipCaseJson "tip-ahead-nonzero" validTipAnnouncement ++ ",\n"
    ++ tipCaseJson "tip-lower-height"
      { validTipAnnouncement with announcedHeight := 99 } ++ ",\n"
    ++ tipCaseJson "tip-equal-local-hash"
      { validTipAnnouncement with
        announcedHeight := 100,
        announcedHashMatchesLocal := true } ++ ",\n"
    ++ tipCaseJson "tip-equal-local-zero-hash-precedence"
      { validTipAnnouncement with
        announcedHeight := 100,
        announcedHashIsZero := true,
        announcedHashMatchesLocal := true } ++ ",\n"
    ++ tipCaseJson "tip-equal-competing-hash"
      { validTipAnnouncement with announcedHeight := 100 } ++ ",\n"
    ++ tipCaseJson "tip-zero-hash"
      { validTipAnnouncement with announcedHashIsZero := true } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_block_chunk_cases\": [\n"
    ++ chunkCaseJson "valid-chunk-exact-cap" validChunk ++ ",\n"
    ++ chunkCaseJson "valid-nonfinal-full-chunk"
      { validChunk with
        chunkBytes := 4,
        totalBytes := 10,
        offset := 0,
        retainedBytes := 0 } ++ ",\n"
    ++ chunkCaseJson "valid-final-remainder-chunk"
      { validChunk with
        chunkBytes := 2,
        totalBytes := 10,
        offset := 8,
        retainedBytes := 8 } ++ ",\n"
    ++ chunkCaseJson "chunk-session-mismatch"
      { validChunk with sessionMatches := false } ++ ",\n"
    ++ chunkCaseJson "chunk-empty"
      { validChunk with chunkBytes := 0 } ++ ",\n"
    ++ chunkCaseJson "chunk-over-cap"
      { validChunk with chunkBytes := 5 } ++ ",\n"
    ++ chunkCaseJson "chunk-undersized-nonfinal"
      { validChunk with
        chunkBytes := 3,
        totalBytes := 10,
        offset := 0,
        retainedBytes := 0 } ++ ",\n"
    ++ chunkCaseJson "chunk-total-zero"
      { validChunk with totalBytes := 0 } ++ ",\n"
    ++ chunkCaseJson "chunk-total-over-cap"
      { validChunk with totalBytes := 17 } ++ ",\n"
    ++ chunkCaseJson "chunk-offset-mismatch"
      { validChunk with offset := 3 } ++ ",\n"
    ++ chunkCaseJson "chunk-end-u64-overflow"
      { validChunk with
        totalBytes := u64Max,
        maxTotalBytes := u64Max,
        offset := u64Max - 1,
        retainedBytes := u64Max - 1 } ++ ",\n"
    ++ chunkCaseJson "chunk-end-past-total"
      { validChunk with totalBytes := 7 } ++ "\n"
    ++ "  ],\n"
    ++ "  \"sync_block_chunk_completion_cases\": [\n"
    ++ completionCaseJson "valid-completion" validCompletion ++ ",\n"
    ++ completionCaseJson "completion-length-mismatch"
      { validCompletion with assembledBytes := 7 } ++ ",\n"
    ++ completionCaseJson "completion-digest-mismatch"
      { validCompletion with digestMatches := false } ++ ",\n"
    ++ completionCaseJson "completion-decode-rejected"
      { validCompletion with exactDecodeAccepts := false } ++ ",\n"
    ++ completionCaseJson "completion-height-mismatch"
      { validCompletion with heightMatches := false } ++ ",\n"
    ++ completionCaseJson "completion-hash-mismatch"
      { validCompletion with hashMatches := false } ++ ",\n"
    ++ completionCaseJson "completion-request-prefix-mismatch"
      { validCompletion with requestPrefixMatches := false } ++ ",\n"
    ++ completionCaseJson "completion-recovery-context-mismatch"
      { validCompletion with recoveryContextMatches := false } ++ "\n"
    ++ "  ]\n"
    ++ "}\n"

def main : IO Unit :=
  IO.print vectorJson
