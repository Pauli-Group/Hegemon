import Hegemon.Resource.BoundedRequestAdmission

namespace Hegemon
namespace Native
namespace SyncBlockChunkAdmission

open Hegemon.Resource.BoundedRequestAdmission

def u64Max : Nat := 18446744073709551615

inductive SyncBlockChunkReject where
  | noMatchingRequest
  | noMatchingOffer
  | responseNotEmpty
  | peerBestBelowRequested
  | sessionCapacity
  | sessionExpired
  | sessionMismatch
  | invalidOutboundTransition
  | emptyChunk
  | chunkTooLarge
  | chunkLengthMismatch
  | totalLenInvalid
  | offsetMismatch
  | chunkEndOverflow
  | chunkEndPastTotal
  | completeLengthMismatch
  | recordDigestMismatch
  | recordDecodeRejected
  | recordHeightMismatch
  | recordHashMismatch
  | requestPrefixMismatch
  | recoveryContextMismatch
deriving DecidableEq, Repr

inductive SyncTipAnnouncementReject where
  | notAhead
  | zeroHash
deriving DecidableEq, Repr

structure SyncChunkFallbackAdmissionInput where
  matchingCompletedRequest : Bool
  responseEmpty : Bool
  peerBestHeight : Nat
  requestedFromHeight : Nat
deriving DecidableEq, Repr

def evaluateSyncChunkFallbackAdmission
    (input : SyncChunkFallbackAdmissionInput) :
    Option SyncBlockChunkReject :=
  if input.matchingCompletedRequest = false then
    some SyncBlockChunkReject.noMatchingRequest
  else if input.responseEmpty = false then
    some SyncBlockChunkReject.responseNotEmpty
  else if input.peerBestHeight < input.requestedFromHeight then
    some SyncBlockChunkReject.peerBestBelowRequested
  else
    none

structure SyncChunkSessionCapacityInput where
  currentSessions : Nat
  maxSessions : Nat
deriving DecidableEq, Repr

def evaluateSyncChunkSessionCapacity
    (input : SyncChunkSessionCapacityInput) :
    Option SyncBlockChunkReject :=
  if input.currentSessions < input.maxSessions then
    none
  else
    some SyncBlockChunkReject.sessionCapacity

inductive SyncChunkServeRequestDisposition where
  | serveNext
  | close
deriving DecidableEq, Repr

structure SyncChunkServeRequestAdmissionInput where
  matchingLiveOfferOrSession : Bool
  tupleMatches : Bool
  offset : Nat
  nextOffset : Nat
  totalLen : Nat
deriving DecidableEq, Repr

def evaluateSyncChunkServeRequestAdmission
    (input : SyncChunkServeRequestAdmissionInput) :
    Except SyncBlockChunkReject SyncChunkServeRequestDisposition :=
  if input.matchingLiveOfferOrSession = false then
    .error SyncBlockChunkReject.noMatchingOffer
  else if input.tupleMatches = false then
    .error SyncBlockChunkReject.sessionMismatch
  else if input.offset = input.totalLen then
    .ok SyncChunkServeRequestDisposition.close
  else if input.offset = input.nextOffset then
    .ok SyncChunkServeRequestDisposition.serveNext
  else
    .error SyncBlockChunkReject.offsetMismatch

structure SyncChunkOfferRequestAdmissionInput where
  matchingLiveOffer : Bool
  heightMatches : Bool
  blockHashMatches : Bool
  recordDigestAbsent : Bool
  offset : Nat
deriving DecidableEq, Repr

def evaluateSyncChunkOfferRequestAdmission
    (input : SyncChunkOfferRequestAdmissionInput) :
    Option SyncBlockChunkReject :=
  if input.matchingLiveOffer = false then
    some SyncBlockChunkReject.noMatchingOffer
  else if input.heightMatches = false ∨
      input.blockHashMatches = false ∨
      input.recordDigestAbsent = false then
    some SyncBlockChunkReject.sessionMismatch
  else if input.offset ≠ 0 then
    some SyncBlockChunkReject.offsetMismatch
  else
    none

inductive SyncChunkOutboundState where
  | inFlight
  | chunkFallback
  | cooldown
  | absent
deriving DecidableEq, Repr

inductive SyncChunkOutboundEvent where
  | admittedEmptyResponse
  | complete
  | abort
deriving DecidableEq, Repr

structure SyncChunkOutboundTransitionInput where
  state : SyncChunkOutboundState
  event : SyncChunkOutboundEvent
deriving DecidableEq, Repr

def evaluateSyncChunkOutboundTransition
    (input : SyncChunkOutboundTransitionInput) :
    Except SyncBlockChunkReject SyncChunkOutboundState :=
  match input.state, input.event with
  | .inFlight, .admittedEmptyResponse => .ok .chunkFallback
  | .chunkFallback, .complete => .ok .absent
  | .chunkFallback, .abort => .ok .cooldown
  | _, _ => .error .invalidOutboundTransition

structure SyncChunkSessionExpiryInput where
  idleElapsedMs : Nat
  maxIdleMs : Nat
  lifetimeElapsedMs : Nat
  maxLifetimeMs : Nat
deriving DecidableEq, Repr

def evaluateSyncChunkSessionExpiry
    (input : SyncChunkSessionExpiryInput) :
    Option SyncBlockChunkReject :=
  if input.maxIdleMs ≤ input.idleElapsedMs ∨
      input.maxLifetimeMs ≤ input.lifetimeElapsedMs then
    some SyncBlockChunkReject.sessionExpired
  else
    none

structure SyncTipAnnouncementAdmissionInput where
  localHeight : Nat
  announcedHeight : Nat
  announcedHashIsZero : Bool
  announcedHashMatchesLocal : Bool
deriving DecidableEq, Repr

def evaluateSyncTipAnnouncementAdmission
    (input : SyncTipAnnouncementAdmissionInput) :
    Option SyncTipAnnouncementReject :=
  if input.announcedHeight < input.localHeight then
    some SyncTipAnnouncementReject.notAhead
  else if input.announcedHeight = input.localHeight then
    if input.announcedHashMatchesLocal then
      some SyncTipAnnouncementReject.notAhead
    else if input.announcedHashIsZero then
      some SyncTipAnnouncementReject.zeroHash
    else
      none
  else if input.announcedHashIsZero then
    some SyncTipAnnouncementReject.zeroHash
  else
    none

structure SyncBlockChunkAdmissionInput where
  sessionMatches : Bool
  chunkBytes : Nat
  maxChunkBytes : Nat
  totalBytes : Nat
  maxTotalBytes : Nat
  offset : Nat
  retainedBytes : Nat
deriving DecidableEq, Repr

def chunkEndOverflowsU64 (input : SyncBlockChunkAdmissionInput) : Bool :=
  u64Max - input.offset < input.chunkBytes

def chunkEnd (input : SyncBlockChunkAdmissionInput) : Nat :=
  input.offset + input.chunkBytes

def expectedChunkBytes (input : SyncBlockChunkAdmissionInput) : Nat :=
  min input.maxChunkBytes (input.totalBytes - input.offset)

def evaluateSyncBlockChunkAdmission
    (input : SyncBlockChunkAdmissionInput) :
    Option SyncBlockChunkReject :=
  if input.sessionMatches = false then
    some SyncBlockChunkReject.sessionMismatch
  else if input.chunkBytes = 0 then
    some SyncBlockChunkReject.emptyChunk
  else if input.maxChunkBytes < input.chunkBytes then
    some SyncBlockChunkReject.chunkTooLarge
  else if input.totalBytes = 0 ∨ input.maxTotalBytes < input.totalBytes then
    some SyncBlockChunkReject.totalLenInvalid
  else if input.offset ≠ input.retainedBytes then
    some SyncBlockChunkReject.offsetMismatch
  else if chunkEndOverflowsU64 input then
    some SyncBlockChunkReject.chunkEndOverflow
  else if input.totalBytes < chunkEnd input then
    some SyncBlockChunkReject.chunkEndPastTotal
  else if input.chunkBytes ≠ expectedChunkBytes input then
    some SyncBlockChunkReject.chunkLengthMismatch
  else
    none

def syncBlockChunkResourcePolicy
    (input : SyncBlockChunkAdmissionInput) : ResourcePolicy :=
  {
    rawByteCap := input.maxChunkBytes,
    decodedByteCap := input.maxTotalBytes,
    itemCountCap := 1,
    itemByteCap := input.maxChunkBytes,
    aggregateByteCap := input.maxTotalBytes,
    workUnitCap := input.maxChunkBytes
  }

def syncBlockChunkResourceRequest
    (input : SyncBlockChunkAdmissionInput) : ResourceRequest :=
  -- `decodedBytes` and `aggregateBytes` here are the accumulated transferred
  -- record bytes after cheap row admission.  They do not model the separate
  -- transient `NativeBlockMeta` allocation and canonical re-encoding during
  -- final exact bincode decode.
  {
    rawBytes := input.chunkBytes,
    decodedBytes := input.retainedBytes + input.chunkBytes,
    itemCount := 1,
    maxItemBytes := input.chunkBytes,
    aggregateBytes := input.retainedBytes + input.chunkBytes,
    workUnits := input.chunkBytes
  }

structure SyncBlockChunkCompletionAdmissionInput where
  assembledBytes : Nat
  totalBytes : Nat
  digestMatches : Bool
  exactDecodeAccepts : Bool
  heightMatches : Bool
  hashMatches : Bool
  requestPrefixMatches : Bool
  recoveryContextMatches : Bool
deriving DecidableEq, Repr

def evaluateSyncBlockChunkCompletionAdmission
    (input : SyncBlockChunkCompletionAdmissionInput) :
    Option SyncBlockChunkReject :=
  if input.assembledBytes != input.totalBytes then
    some SyncBlockChunkReject.completeLengthMismatch
  else if input.digestMatches = false then
    some SyncBlockChunkReject.recordDigestMismatch
  else if input.exactDecodeAccepts = false then
    some SyncBlockChunkReject.recordDecodeRejected
  else if input.heightMatches = false then
    some SyncBlockChunkReject.recordHeightMismatch
  else if input.hashMatches = false then
    some SyncBlockChunkReject.recordHashMismatch
  else if input.requestPrefixMatches = false then
    some SyncBlockChunkReject.requestPrefixMismatch
  else if input.recoveryContextMatches = false then
    some SyncBlockChunkReject.recoveryContextMismatch
  else
    none

theorem accepted_chunk_retained_bytes_within_total
    {input : SyncBlockChunkAdmissionInput}
    (accepted : evaluateSyncBlockChunkAdmission input = none) :
    input.retainedBytes + input.chunkBytes ≤ input.totalBytes := by
  unfold evaluateSyncBlockChunkAdmission at accepted
  by_cases sessionMismatch : input.sessionMatches = false
  · simp [sessionMismatch] at accepted
  · by_cases empty : input.chunkBytes = 0
    · simp [sessionMismatch, empty] at accepted
    · by_cases chunkOver : input.maxChunkBytes < input.chunkBytes
      · simp [sessionMismatch, empty, chunkOver] at accepted
      · by_cases totalInvalid :
        input.totalBytes = 0 ∨ input.maxTotalBytes < input.totalBytes
        · simp [sessionMismatch, empty, chunkOver, totalInvalid] at accepted
        · by_cases offsetMismatch : input.offset ≠ input.retainedBytes
          · simp [sessionMismatch, empty, chunkOver, totalInvalid,
              offsetMismatch] at accepted
          · by_cases overflow : chunkEndOverflowsU64 input
            · simp [sessionMismatch, empty, chunkOver, totalInvalid,
                offsetMismatch, overflow] at accepted
            · by_cases pastTotal : input.totalBytes < chunkEnd input
              · simp [sessionMismatch, empty, chunkOver, totalInvalid,
                  offsetMismatch, overflow, pastTotal] at accepted
              · have offsetEq : input.offset = input.retainedBytes := by
                  omega
                have endWithin : chunkEnd input ≤ input.totalBytes :=
                  Nat.le_of_not_gt pastTotal
                simpa [chunkEnd, offsetEq] using endWithin

theorem accepted_chunk_total_within_cap
    {input : SyncBlockChunkAdmissionInput}
    (accepted : evaluateSyncBlockChunkAdmission input = none) :
    input.totalBytes ≤ input.maxTotalBytes := by
  unfold evaluateSyncBlockChunkAdmission at accepted
  by_cases sessionMismatch : input.sessionMatches = false
  · simp [sessionMismatch] at accepted
  · by_cases empty : input.chunkBytes = 0
    · simp [sessionMismatch, empty] at accepted
    · by_cases chunkOver : input.maxChunkBytes < input.chunkBytes
      · simp [sessionMismatch, empty, chunkOver] at accepted
      · by_cases totalInvalid :
          input.totalBytes = 0 ∨ input.maxTotalBytes < input.totalBytes
        · simp [sessionMismatch, empty, chunkOver, totalInvalid] at accepted
        · have totalNotOver :
              ¬ input.maxTotalBytes < input.totalBytes :=
            (not_or.mp totalInvalid).2
          exact Nat.le_of_not_gt totalNotOver

theorem accepted_chunk_exposes_bounded_request_facts
    {input : SyncBlockChunkAdmissionInput}
    (accepted : evaluateSyncBlockChunkAdmission input = none) :
    AcceptedBoundedRequestFacts
      (syncBlockChunkResourcePolicy input)
      (syncBlockChunkResourceRequest input) := by
  have retainedWithin := accepted_chunk_retained_bytes_within_total accepted
  have totalWithin := accepted_chunk_total_within_cap accepted
  have chunkWithin : input.chunkBytes ≤ input.maxChunkBytes := by
    unfold evaluateSyncBlockChunkAdmission at accepted
    by_cases sessionMismatch : input.sessionMatches = false
    · simp [sessionMismatch] at accepted
    · by_cases empty : input.chunkBytes = 0
      · simp [sessionMismatch, empty] at accepted
      · by_cases chunkOver : input.maxChunkBytes < input.chunkBytes
        · simp [sessionMismatch, empty, chunkOver] at accepted
        · omega
  have assembledWithin :
      input.retainedBytes + input.chunkBytes ≤ input.maxTotalBytes :=
    Nat.le_trans retainedWithin totalWithin
  have boundedAccepted :
      evaluateBoundedRequest
        (syncBlockChunkResourcePolicy input)
        (syncBlockChunkResourceRequest input) = none := by
    apply complete_bounded_request_accepts
    unfold resourcePreconditions
    simp only [syncBlockChunkResourcePolicy, syncBlockChunkResourceRequest]
    omega
  exact accepted_bounded_request_exposes_all_caps boundedAccepted

theorem accepted_chunk_has_canonical_length
    {input : SyncBlockChunkAdmissionInput}
    (accepted : evaluateSyncBlockChunkAdmission input = none) :
    input.chunkBytes = expectedChunkBytes input := by
  unfold evaluateSyncBlockChunkAdmission at accepted
  by_cases sessionMismatch : input.sessionMatches = false
  · simp [sessionMismatch] at accepted
  · by_cases empty : input.chunkBytes = 0
    · simp [sessionMismatch, empty] at accepted
    · by_cases chunkOver : input.maxChunkBytes < input.chunkBytes
      · simp [sessionMismatch, empty, chunkOver] at accepted
      · by_cases totalInvalid :
          input.totalBytes = 0 ∨ input.maxTotalBytes < input.totalBytes
        · simp [sessionMismatch, empty, chunkOver, totalInvalid] at accepted
        · by_cases offsetMismatch : input.offset ≠ input.retainedBytes
          · simp [sessionMismatch, empty, chunkOver, totalInvalid,
              offsetMismatch] at accepted
          · by_cases overflow : chunkEndOverflowsU64 input
            · simp [sessionMismatch, empty, chunkOver, totalInvalid,
                offsetMismatch, overflow] at accepted
            · by_cases pastTotal : input.totalBytes < chunkEnd input
              · simp [sessionMismatch, empty, chunkOver, totalInvalid,
                  offsetMismatch, overflow, pastTotal] at accepted
              · by_cases lengthMismatch :
                  input.chunkBytes ≠ expectedChunkBytes input
                · simp [sessionMismatch, empty, chunkOver, totalInvalid,
                    offsetMismatch, overflow, pastTotal, lengthMismatch] at accepted
                · exact Classical.not_not.mp lengthMismatch

theorem accepted_nonfinal_chunk_fills_cap
    {input : SyncBlockChunkAdmissionInput}
    (accepted : evaluateSyncBlockChunkAdmission input = none)
    (fullChunkRemains : input.maxChunkBytes ≤ input.totalBytes - input.offset) :
    input.chunkBytes = input.maxChunkBytes := by
  rw [accepted_chunk_has_canonical_length accepted]
  simp [expectedChunkBytes, Nat.min_eq_left fullChunkRemains]

theorem accepted_final_chunk_matches_remainder
    {input : SyncBlockChunkAdmissionInput}
    (accepted : evaluateSyncBlockChunkAdmission input = none)
    (finalRemainder : input.totalBytes - input.offset ≤ input.maxChunkBytes) :
    input.chunkBytes = input.totalBytes - input.offset := by
  rw [accepted_chunk_has_canonical_length accepted]
  simp [expectedChunkBytes, Nat.min_eq_right finalRemainder]

def validFallback : SyncChunkFallbackAdmissionInput := {
  matchingCompletedRequest := true,
  responseEmpty := true,
  peerBestHeight := 120,
  requestedFromHeight := 100
}

def validCapacity : SyncChunkSessionCapacityInput := {
  currentSessions := 1,
  maxSessions := 2
}

def validServeRequest : SyncChunkServeRequestAdmissionInput := {
  matchingLiveOfferOrSession := true,
  tupleMatches := true,
  offset := 4,
  nextOffset := 4,
  totalLen := 8
}

def validOfferRequest : SyncChunkOfferRequestAdmissionInput := {
  matchingLiveOffer := true,
  heightMatches := true,
  blockHashMatches := true,
  recordDigestAbsent := true,
  offset := 0
}

def validExpiry : SyncChunkSessionExpiryInput := {
  idleElapsedMs := 29999,
  maxIdleMs := 30000,
  lifetimeElapsedMs := 119999,
  maxLifetimeMs := 120000
}

def validTipAnnouncement : SyncTipAnnouncementAdmissionInput := {
  localHeight := 100,
  announcedHeight := 101,
  announcedHashIsZero := false,
  announcedHashMatchesLocal := false
}

def validChunk : SyncBlockChunkAdmissionInput := {
  sessionMatches := true,
  chunkBytes := 4,
  maxChunkBytes := 4,
  totalBytes := 8,
  maxTotalBytes := 16,
  offset := 4,
  retainedBytes := 4
}

def validCompletion : SyncBlockChunkCompletionAdmissionInput := {
  assembledBytes := 8,
  totalBytes := 8,
  digestMatches := true,
  exactDecodeAccepts := true,
  heightMatches := true,
  hashMatches := true,
  requestPrefixMatches := true,
  recoveryContextMatches := true
}

theorem valid_fallback_accepts :
    evaluateSyncChunkFallbackAdmission validFallback = none := by
  decide

theorem fallback_without_matching_request_rejects :
    evaluateSyncChunkFallbackAdmission
      { validFallback with matchingCompletedRequest := false } =
        some SyncBlockChunkReject.noMatchingRequest := by
  decide

theorem fallback_peer_best_below_requested_rejects :
    evaluateSyncChunkFallbackAdmission
      { validFallback with peerBestHeight := 99 } =
        some SyncBlockChunkReject.peerBestBelowRequested := by
  decide

theorem session_capacity_exact_limit_rejects :
    evaluateSyncChunkSessionCapacity
      { validCapacity with currentSessions := 2 } =
        some SyncBlockChunkReject.sessionCapacity := by
  decide

theorem matching_offer_exact_next_offset_serves :
    evaluateSyncChunkServeRequestAdmission validServeRequest =
      .ok SyncChunkServeRequestDisposition.serveNext := by
  rfl

theorem serve_request_without_matching_offer_rejects :
    evaluateSyncChunkServeRequestAdmission
      { validServeRequest with matchingLiveOfferOrSession := false } =
        .error SyncBlockChunkReject.noMatchingOffer := by
  rfl

theorem serve_request_tuple_mismatch_rejects :
    evaluateSyncChunkServeRequestAdmission
      { validServeRequest with tupleMatches := false } =
        .error SyncBlockChunkReject.sessionMismatch := by
  rfl

theorem serve_request_wrong_next_offset_rejects :
    evaluateSyncChunkServeRequestAdmission
      { validServeRequest with offset := 3 } =
        .error SyncBlockChunkReject.offsetMismatch := by
  rfl

theorem serve_request_total_offset_closes :
    evaluateSyncChunkServeRequestAdmission
      { validServeRequest with offset := 8 } =
        .ok SyncChunkServeRequestDisposition.close := by
  rfl

theorem matching_offer_initial_request_accepts :
    evaluateSyncChunkOfferRequestAdmission validOfferRequest = none := by
  decide

theorem offer_request_without_matching_offer_rejects :
    evaluateSyncChunkOfferRequestAdmission
      { validOfferRequest with matchingLiveOffer := false } =
        some SyncBlockChunkReject.noMatchingOffer := by
  decide

theorem offer_request_tuple_mismatch_rejects :
    evaluateSyncChunkOfferRequestAdmission
      { validOfferRequest with recordDigestAbsent := false } =
        some SyncBlockChunkReject.sessionMismatch := by
  decide

theorem offer_request_nonzero_offset_rejects_before_record_load :
    evaluateSyncChunkOfferRequestAdmission
      { validOfferRequest with offset := 1 } =
        some SyncBlockChunkReject.offsetMismatch := by
  decide

theorem offer_request_u64_max_offset_rejects_before_record_load :
    evaluateSyncChunkOfferRequestAdmission
      { validOfferRequest with offset := u64Max } =
        some SyncBlockChunkReject.offsetMismatch := by
  decide

theorem admitted_empty_response_enters_chunk_fallback :
    evaluateSyncChunkOutboundTransition {
      state := .inFlight,
      event := .admittedEmptyResponse
    } = .ok .chunkFallback := by
  rfl

theorem completed_chunk_fallback_removes_request :
    evaluateSyncChunkOutboundTransition {
      state := .chunkFallback,
      event := .complete
    } = .ok .absent := by
  rfl

theorem aborted_chunk_fallback_enters_cooldown :
    evaluateSyncChunkOutboundTransition {
      state := .chunkFallback,
      event := .abort
    } = .ok .cooldown := by
  rfl

theorem duplicate_empty_response_transition_rejects :
    evaluateSyncChunkOutboundTransition {
      state := .chunkFallback,
      event := .admittedEmptyResponse
    } = .error .invalidOutboundTransition := by
  rfl

theorem live_chunk_session_accepts :
    evaluateSyncChunkSessionExpiry validExpiry = none := by
  decide

theorem chunk_session_idle_exact_limit_expires :
    evaluateSyncChunkSessionExpiry
      { validExpiry with idleElapsedMs := 30000 } =
        some SyncBlockChunkReject.sessionExpired := by
  decide

theorem chunk_session_lifetime_exact_limit_expires :
    evaluateSyncChunkSessionExpiry
      { validExpiry with lifetimeElapsedMs := 120000 } =
        some SyncBlockChunkReject.sessionExpired := by
  decide

theorem valid_tip_announcement_accepts :
    evaluateSyncTipAnnouncementAdmission validTipAnnouncement = none := by
  decide

theorem tip_announcement_not_ahead_rejects :
    evaluateSyncTipAnnouncementAdmission
      { validTipAnnouncement with announcedHeight := 99 } =
        some SyncTipAnnouncementReject.notAhead := by
  decide

theorem tip_announcement_equal_local_hash_rejects :
    evaluateSyncTipAnnouncementAdmission
      { validTipAnnouncement with
        announcedHeight := 100,
        announcedHashMatchesLocal := true } =
        some SyncTipAnnouncementReject.notAhead := by
  decide

theorem tip_announcement_equal_local_hash_precedes_zero_hash :
    evaluateSyncTipAnnouncementAdmission
      { validTipAnnouncement with
        announcedHeight := 100,
        announcedHashIsZero := true,
        announcedHashMatchesLocal := true } =
        some SyncTipAnnouncementReject.notAhead := by
  decide

theorem tip_announcement_equal_competing_hash_accepts :
    evaluateSyncTipAnnouncementAdmission
      { validTipAnnouncement with announcedHeight := 100 } = none := by
  decide

theorem tip_announcement_zero_hash_rejects :
    evaluateSyncTipAnnouncementAdmission
      { validTipAnnouncement with announcedHashIsZero := true } =
        some SyncTipAnnouncementReject.zeroHash := by
  decide

theorem valid_chunk_accepts :
    evaluateSyncBlockChunkAdmission validChunk = none := by
  decide

theorem valid_nonfinal_full_chunk_accepts :
    evaluateSyncBlockChunkAdmission {
      validChunk with
      chunkBytes := 4,
      totalBytes := 10,
      offset := 0,
      retainedBytes := 0
    } = none := by
  decide

theorem valid_final_remainder_chunk_accepts :
    evaluateSyncBlockChunkAdmission {
      validChunk with
      chunkBytes := 2,
      totalBytes := 10,
      offset := 8,
      retainedBytes := 8
    } = none := by
  decide

theorem empty_chunk_rejects :
    evaluateSyncBlockChunkAdmission
      { validChunk with chunkBytes := 0 } =
        some SyncBlockChunkReject.emptyChunk := by
  decide

theorem oversized_chunk_rejects :
    evaluateSyncBlockChunkAdmission
      { validChunk with chunkBytes := 5 } =
        some SyncBlockChunkReject.chunkTooLarge := by
  decide

theorem undersized_nonfinal_chunk_rejects :
    evaluateSyncBlockChunkAdmission {
      validChunk with
      chunkBytes := 3,
      totalBytes := 10,
      offset := 0,
      retainedBytes := 0
    } = some SyncBlockChunkReject.chunkLengthMismatch := by
  decide

theorem offset_mismatch_rejects :
    evaluateSyncBlockChunkAdmission
      { validChunk with offset := 3 } =
        some SyncBlockChunkReject.offsetMismatch := by
  decide

theorem chunk_end_overflow_rejects :
    evaluateSyncBlockChunkAdmission
      { validChunk with
        totalBytes := u64Max,
        maxTotalBytes := u64Max,
        offset := u64Max - 1,
        retainedBytes := u64Max - 1 } =
        some SyncBlockChunkReject.chunkEndOverflow := by
  decide

theorem chunk_end_past_total_rejects :
    evaluateSyncBlockChunkAdmission
      { validChunk with totalBytes := 7 } =
        some SyncBlockChunkReject.chunkEndPastTotal := by
  decide

theorem valid_completion_accepts :
    evaluateSyncBlockChunkCompletionAdmission validCompletion = none := by
  decide

theorem completion_digest_mismatch_rejects :
    evaluateSyncBlockChunkCompletionAdmission
      { validCompletion with digestMatches := false } =
        some SyncBlockChunkReject.recordDigestMismatch := by
  decide

theorem completion_decode_rejects_after_digest_accepts :
    evaluateSyncBlockChunkCompletionAdmission
      { validCompletion with exactDecodeAccepts := false } =
        some SyncBlockChunkReject.recordDecodeRejected := by
  decide

theorem completion_context_mismatch_rejects :
    evaluateSyncBlockChunkCompletionAdmission
      { validCompletion with recoveryContextMatches := false } =
        some SyncBlockChunkReject.recoveryContextMismatch := by
  decide

end SyncBlockChunkAdmission
end Native
end Hegemon
