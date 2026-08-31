//! Bounded fallback transport for one canonical native block record that
//! cannot fit in the legacy sync-response frame.

use super::*;
use sha2::{Digest, Sha256};

const NATIVE_SYNC_CHUNK_DIGEST_DOMAIN: &[u8] = b"hegemon-native-sync-block-record-v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncChunkFallbackAdmissionInput {
    pub(crate) matching_completed_request: bool,
    pub(crate) response_empty: bool,
    pub(crate) peer_best_height: u64,
    pub(crate) requested_from_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncBlockChunkAdmissionInput {
    /// True only for the exact authenticated live receive-session tuple.
    pub(crate) session_matches: bool,
    pub(crate) chunk_len: usize,
    pub(crate) max_chunk_bytes: usize,
    pub(crate) total_len: u64,
    pub(crate) max_total_len: u64,
    pub(crate) offset: u64,
    pub(crate) retained_len: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncBlockChunkCompletionAdmissionInput {
    pub(crate) assembled_len: usize,
    pub(crate) total_len: u64,
    pub(crate) digest_matches: bool,
    pub(crate) exact_decode_accepts: bool,
    pub(crate) height_matches: bool,
    pub(crate) hash_matches: bool,
    pub(crate) request_prefix_matches: bool,
    pub(crate) recovery_context_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncChunkSessionCapacityInput {
    pub(crate) current_sessions: usize,
    pub(crate) max_sessions: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncChunkSessionExpiryInput {
    pub(crate) idle_elapsed_ms: u64,
    pub(crate) max_idle_ms: u64,
    pub(crate) lifetime_elapsed_ms: u64,
    pub(crate) max_lifetime_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncChunkServeRequestAdmissionInput {
    pub(crate) matching_live_offer_or_session: bool,
    pub(crate) tuple_matches: bool,
    pub(crate) offset: u64,
    pub(crate) next_offset: u64,
    pub(crate) total_len: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncChunkOfferRequestAdmissionInput {
    pub(crate) matching_live_offer: bool,
    pub(crate) height_matches: bool,
    pub(crate) block_hash_matches: bool,
    pub(crate) record_digest_absent: bool,
    pub(crate) offset: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncChunkServeRequestDisposition {
    ServeNext,
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncChunkOutboundState {
    InFlight,
    ChunkFallback,
    Cooldown,
    Absent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncChunkOutboundEvent {
    AdmittedEmptyResponse,
    Complete,
    Abort,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncChunkOutboundTransitionInput {
    pub(crate) state: NativeSyncChunkOutboundState,
    pub(crate) event: NativeSyncChunkOutboundEvent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncChunkAdmissionRejection {
    NoMatchingRequest,
    NoMatchingOffer,
    ResponseNotEmpty,
    PeerBestBelowRequested,
    SessionCapacity,
    SessionMismatch,
    SessionExpired,
    InvalidOutboundTransition,
    EmptyChunk,
    ChunkTooLarge,
    ChunkLengthMismatch,
    TotalLenInvalid,
    OffsetMismatch,
    ChunkEndOverflow,
    ChunkEndPastTotal,
    CompleteLengthMismatch,
    RecordDigestMismatch,
    RecordDecodeRejected,
    RecordHeightMismatch,
    RecordHashMismatch,
    RequestPrefixMismatch,
    RecoveryContextMismatch,
}

impl NativeSyncChunkAdmissionRejection {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NoMatchingRequest => "no_matching_request",
            Self::NoMatchingOffer => "no_matching_offer",
            Self::ResponseNotEmpty => "response_not_empty",
            Self::PeerBestBelowRequested => "peer_best_below_requested",
            Self::SessionCapacity => "session_capacity",
            Self::SessionMismatch => "session_mismatch",
            Self::SessionExpired => "session_expired",
            Self::InvalidOutboundTransition => "invalid_outbound_transition",
            Self::EmptyChunk => "empty_chunk",
            Self::ChunkTooLarge => "chunk_too_large",
            Self::ChunkLengthMismatch => "chunk_length_mismatch",
            Self::TotalLenInvalid => "total_len_invalid",
            Self::OffsetMismatch => "offset_mismatch",
            Self::ChunkEndOverflow => "chunk_end_overflow",
            Self::ChunkEndPastTotal => "chunk_end_past_total",
            Self::CompleteLengthMismatch => "complete_length_mismatch",
            Self::RecordDigestMismatch => "record_digest_mismatch",
            Self::RecordDecodeRejected => "record_decode_rejected",
            Self::RecordHeightMismatch => "record_height_mismatch",
            Self::RecordHashMismatch => "record_hash_mismatch",
            Self::RequestPrefixMismatch => "request_prefix_mismatch",
            Self::RecoveryContextMismatch => "recovery_context_mismatch",
        }
    }
}

pub(crate) fn evaluate_native_sync_chunk_fallback_admission(
    input: NativeSyncChunkFallbackAdmissionInput,
) -> Result<(), NativeSyncChunkAdmissionRejection> {
    if !input.matching_completed_request {
        Err(NativeSyncChunkAdmissionRejection::NoMatchingRequest)
    } else if !input.response_empty {
        Err(NativeSyncChunkAdmissionRejection::ResponseNotEmpty)
    } else if input.peer_best_height < input.requested_from_height {
        Err(NativeSyncChunkAdmissionRejection::PeerBestBelowRequested)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_sync_chunk_session_capacity(
    input: NativeSyncChunkSessionCapacityInput,
) -> Result<(), NativeSyncChunkAdmissionRejection> {
    if input.current_sessions >= input.max_sessions {
        Err(NativeSyncChunkAdmissionRejection::SessionCapacity)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_sync_chunk_session_expiry(
    input: NativeSyncChunkSessionExpiryInput,
) -> Result<(), NativeSyncChunkAdmissionRejection> {
    if input.idle_elapsed_ms >= input.max_idle_ms
        || input.lifetime_elapsed_ms >= input.max_lifetime_ms
    {
        Err(NativeSyncChunkAdmissionRejection::SessionExpired)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_sync_chunk_serve_request_admission(
    input: NativeSyncChunkServeRequestAdmissionInput,
) -> Result<NativeSyncChunkServeRequestDisposition, NativeSyncChunkAdmissionRejection> {
    if !input.matching_live_offer_or_session {
        Err(NativeSyncChunkAdmissionRejection::NoMatchingOffer)
    } else if !input.tuple_matches {
        Err(NativeSyncChunkAdmissionRejection::SessionMismatch)
    } else if input.offset == input.total_len {
        Ok(NativeSyncChunkServeRequestDisposition::Close)
    } else if input.offset == input.next_offset {
        Ok(NativeSyncChunkServeRequestDisposition::ServeNext)
    } else {
        Err(NativeSyncChunkAdmissionRejection::OffsetMismatch)
    }
}

/// Fail-closed admission for the first request against an `Offered` server
/// session, before the record length is known or any storage work starts.
pub(crate) fn evaluate_native_sync_chunk_offer_request_admission(
    input: NativeSyncChunkOfferRequestAdmissionInput,
) -> Result<(), NativeSyncChunkAdmissionRejection> {
    if !input.matching_live_offer {
        Err(NativeSyncChunkAdmissionRejection::NoMatchingOffer)
    } else if !input.height_matches || !input.block_hash_matches || !input.record_digest_absent {
        Err(NativeSyncChunkAdmissionRejection::SessionMismatch)
    } else if input.offset != 0 {
        Err(NativeSyncChunkAdmissionRejection::OffsetMismatch)
    } else {
        Ok(())
    }
}

pub(crate) fn evaluate_native_sync_chunk_outbound_transition(
    input: NativeSyncChunkOutboundTransitionInput,
) -> Result<NativeSyncChunkOutboundState, NativeSyncChunkAdmissionRejection> {
    match (input.state, input.event) {
        (
            NativeSyncChunkOutboundState::InFlight,
            NativeSyncChunkOutboundEvent::AdmittedEmptyResponse,
        ) => Ok(NativeSyncChunkOutboundState::ChunkFallback),
        (NativeSyncChunkOutboundState::ChunkFallback, NativeSyncChunkOutboundEvent::Complete) => {
            Ok(NativeSyncChunkOutboundState::Absent)
        }
        (NativeSyncChunkOutboundState::ChunkFallback, NativeSyncChunkOutboundEvent::Abort) => {
            Ok(NativeSyncChunkOutboundState::Cooldown)
        }
        _ => Err(NativeSyncChunkAdmissionRejection::InvalidOutboundTransition),
    }
}

pub(crate) fn evaluate_native_sync_block_chunk_admission(
    input: NativeSyncBlockChunkAdmissionInput,
) -> Result<(), NativeSyncChunkAdmissionRejection> {
    if !input.session_matches {
        return Err(NativeSyncChunkAdmissionRejection::SessionMismatch);
    }
    if input.chunk_len == 0 {
        return Err(NativeSyncChunkAdmissionRejection::EmptyChunk);
    }
    if input.chunk_len > input.max_chunk_bytes {
        return Err(NativeSyncChunkAdmissionRejection::ChunkTooLarge);
    }
    if input.total_len == 0 || input.total_len > input.max_total_len {
        return Err(NativeSyncChunkAdmissionRejection::TotalLenInvalid);
    }
    let retained_len = u64::try_from(input.retained_len)
        .map_err(|_| NativeSyncChunkAdmissionRejection::OffsetMismatch)?;
    if input.offset != retained_len {
        return Err(NativeSyncChunkAdmissionRejection::OffsetMismatch);
    }
    let chunk_len = u64::try_from(input.chunk_len)
        .map_err(|_| NativeSyncChunkAdmissionRejection::ChunkEndOverflow)?;
    let chunk_end = input
        .offset
        .checked_add(chunk_len)
        .ok_or(NativeSyncChunkAdmissionRejection::ChunkEndOverflow)?;
    if chunk_end > input.total_len {
        return Err(NativeSyncChunkAdmissionRejection::ChunkEndPastTotal);
    }
    let expected_chunk_len = input
        .total_len
        .saturating_sub(input.offset)
        .min(u64::try_from(input.max_chunk_bytes).unwrap_or(u64::MAX));
    if chunk_len != expected_chunk_len {
        return Err(NativeSyncChunkAdmissionRejection::ChunkLengthMismatch);
    }
    Ok(())
}

pub(crate) fn evaluate_native_sync_block_chunk_completion_admission(
    input: NativeSyncBlockChunkCompletionAdmissionInput,
) -> Result<(), NativeSyncChunkAdmissionRejection> {
    if u64::try_from(input.assembled_len).ok() != Some(input.total_len) {
        Err(NativeSyncChunkAdmissionRejection::CompleteLengthMismatch)
    } else if !input.digest_matches {
        Err(NativeSyncChunkAdmissionRejection::RecordDigestMismatch)
    } else if !input.exact_decode_accepts {
        Err(NativeSyncChunkAdmissionRejection::RecordDecodeRejected)
    } else if !input.height_matches {
        Err(NativeSyncChunkAdmissionRejection::RecordHeightMismatch)
    } else if !input.hash_matches {
        Err(NativeSyncChunkAdmissionRejection::RecordHashMismatch)
    } else if !input.request_prefix_matches {
        Err(NativeSyncChunkAdmissionRejection::RequestPrefixMismatch)
    } else if !input.recovery_context_matches {
        Err(NativeSyncChunkAdmissionRejection::RecoveryContextMismatch)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncTipAnnouncementAdmissionInput {
    pub(crate) local_height: u64,
    pub(crate) announced_height: u64,
    pub(crate) announced_hash_is_zero: bool,
    pub(crate) announced_hash_matches_local: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncTipAnnouncementAdmissionRejection {
    NotAhead,
    ZeroHash,
}

impl NativeSyncTipAnnouncementAdmissionRejection {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::NotAhead => "not_ahead",
            Self::ZeroHash => "zero_hash",
        }
    }
}

pub(crate) fn evaluate_native_sync_tip_announcement_admission(
    input: NativeSyncTipAnnouncementAdmissionInput,
) -> Result<(), NativeSyncTipAnnouncementAdmissionRejection> {
    if input.announced_height < input.local_height
        || (input.announced_height == input.local_height && input.announced_hash_matches_local)
    {
        Err(NativeSyncTipAnnouncementAdmissionRejection::NotAhead)
    } else if input.announced_hash_is_zero {
        Err(NativeSyncTipAnnouncementAdmissionRejection::ZeroHash)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeSyncTipAnnouncement {
    pub(crate) best_height: u64,
    pub(crate) best_hash: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeSyncBlockChunkRequest {
    pub(crate) height: u64,
    pub(crate) block_hash: Option<[u8; 32]>,
    pub(crate) record_digest: Option<[u8; 32]>,
    pub(crate) offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeSyncBlockChunk {
    pub(crate) best_height: u64,
    pub(crate) height: u64,
    pub(crate) block_hash: [u8; 32],
    pub(crate) record_encoding: u8,
    pub(crate) record_digest: [u8; 32],
    pub(crate) total_len: u64,
    pub(crate) offset: u64,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncChunkOffer {
    pub(crate) height: u64,
    pub(crate) block_hash: [u8; 32],
}

pub(crate) enum NativeSyncChunkServeSession {
    Offered {
        range: NativeSyncRange,
        offer: NativeSyncChunkOffer,
        started_at: Instant,
        last_activity_at: Instant,
    },
    Loading {
        range: NativeSyncRange,
        offer: NativeSyncChunkOffer,
        started_at: Instant,
        last_activity_at: Instant,
    },
    Serving {
        range: NativeSyncRange,
        offer: NativeSyncChunkOffer,
        record_encoding: u8,
        record_digest: [u8; 32],
        record: sled::IVec,
        next_offset: u64,
        started_at: Instant,
        last_activity_at: Instant,
    },
}

impl NativeSyncChunkServeSession {
    fn timestamps(&self) -> (Instant, Instant) {
        match self {
            Self::Offered {
                started_at,
                last_activity_at,
                ..
            }
            | Self::Loading {
                started_at,
                last_activity_at,
                ..
            }
            | Self::Serving {
                started_at,
                last_activity_at,
                ..
            } => (*started_at, *last_activity_at),
        }
    }
}

pub(crate) struct NativeSyncChunkReceiveSession {
    pub(crate) peer_best_height: u64,
    pub(crate) expected_height: u64,
    pub(crate) completed_request: NativeCompletedSyncRequest,
    pub(crate) block_hash: Option<[u8; 32]>,
    pub(crate) record_encoding: Option<u8>,
    pub(crate) record_digest: Option<[u8; 32]>,
    pub(crate) total_len: Option<u64>,
    pub(crate) retained_len: usize,
    pub(crate) chunks: Vec<Vec<u8>>,
    pub(crate) started_at: Instant,
    pub(crate) last_activity_at: Instant,
}

#[derive(Default)]
pub(crate) struct NativeSyncChunkSessions {
    serve: BTreeMap<PeerId, NativeSyncChunkServeSession>,
    receive: BTreeMap<PeerId, NativeSyncChunkReceiveSession>,
}

impl NativeSyncChunkSessions {
    fn len(&self) -> usize {
        self.serve.len().saturating_add(self.receive.len())
    }
}

#[derive(Debug)]
pub(crate) enum NativeSyncChunkReceiveProgress {
    NeedMore(NativeSyncBlockChunkRequest),
    Complete {
        peer_best_height: u64,
        completed_request: NativeCompletedSyncRequest,
        block: Box<NativeBlockMeta>,
        close_request: NativeSyncBlockChunkRequest,
    },
}

fn native_sync_chunk_expiry_input(
    started_at: Instant,
    last_activity_at: Instant,
    now: Instant,
) -> NativeSyncChunkSessionExpiryInput {
    NativeSyncChunkSessionExpiryInput {
        idle_elapsed_ms: duration_millis_u64(now.saturating_duration_since(last_activity_at)),
        max_idle_ms: duration_millis_u64(NATIVE_SYNC_CHUNK_SESSION_TTL),
        lifetime_elapsed_ms: duration_millis_u64(now.saturating_duration_since(started_at)),
        max_lifetime_ms: duration_millis_u64(NATIVE_SYNC_CHUNK_SESSION_MAX_LIFETIME),
    }
}

fn native_sync_chunk_session_is_live(
    started_at: Instant,
    last_activity_at: Instant,
    now: Instant,
) -> bool {
    evaluate_native_sync_chunk_session_expiry(native_sync_chunk_expiry_input(
        started_at,
        last_activity_at,
        now,
    ))
    .is_ok()
}

pub(crate) fn native_sync_chunk_record_digest(
    record_encoding: u8,
    height: u64,
    block_hash: [u8; 32],
    total_len: u64,
    bytes: &[u8],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(NATIVE_SYNC_CHUNK_DIGEST_DOMAIN);
    digest.update([record_encoding]);
    digest.update(height.to_le_bytes());
    digest.update(block_hash);
    digest.update(total_len.to_le_bytes());
    digest.update(bytes);
    digest.finalize().into()
}

pub(crate) fn decode_native_sync_chunk_record_exact(
    record_encoding: u8,
    bytes: &[u8],
) -> Result<NativeBlockMeta> {
    match record_encoding {
        NATIVE_SYNC_CHUNK_RECORD_ENCODING_LEGACY_V1 => {
            bincode_deserialize_legacy_v1_native_block_meta_exact(
                bytes,
                "legacy V1 native sync chunk block metadata",
            )
        }
        NATIVE_SYNC_CHUNK_RECORD_ENCODING_CURRENT_V2 => {
            bincode_deserialize_current_native_block_meta_exact(
                bytes,
                "current V2 native sync chunk block metadata",
            )
        }
        _ => Err(anyhow!(
            "unsupported native sync chunk record encoding {record_encoding}"
        )),
    }
}

fn outbound_chunk_state(state: NativeOutboundSyncRequestState) -> NativeSyncChunkOutboundState {
    match state {
        NativeOutboundSyncRequestState::InFlight => NativeSyncChunkOutboundState::InFlight,
        NativeOutboundSyncRequestState::Cooldown => NativeSyncChunkOutboundState::Cooldown,
        NativeOutboundSyncRequestState::ChunkFallback => {
            NativeSyncChunkOutboundState::ChunkFallback
        }
    }
}

impl NativeNode {
    pub(crate) fn best_height(&self) -> u64 {
        self.state.read().best.height
    }

    pub(crate) fn best_height_and_hash(&self) -> (u64, [u8; 32]) {
        let state = self.state.read();
        (state.best.height, state.best.hash)
    }

    #[cfg(test)]
    pub(crate) fn native_sync_chunk_session_counts(&self) -> (usize, usize, usize) {
        let sessions = self.sync_chunk_sessions.lock();
        (sessions.serve.len(), sessions.receive.len(), sessions.len())
    }

    pub(crate) fn begin_native_sync_chunk_receive_worker(&self, peer_id: PeerId) -> bool {
        let mut workers = self.sync_chunk_receive_in_flight_peers.lock();
        if workers.contains(&peer_id)
            || evaluate_native_sync_chunk_session_capacity(NativeSyncChunkSessionCapacityInput {
                current_sessions: workers.len(),
                max_sessions: MAX_NATIVE_SYNC_CHUNK_SESSIONS,
            })
            .is_err()
        {
            return false;
        }
        workers.insert(peer_id)
    }

    pub(crate) fn end_native_sync_chunk_receive_worker(&self, peer_id: PeerId) {
        self.sync_chunk_receive_in_flight_peers
            .lock()
            .remove(&peer_id);
    }

    #[cfg(test)]
    pub(crate) fn native_sync_chunk_receive_worker_count(&self) -> usize {
        self.sync_chunk_receive_in_flight_peers.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn native_sync_chunk_record_load_count(&self) -> u64 {
        self.sync_chunk_record_load_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn native_sync_chunk_record_decode_count(&self) -> u64 {
        self.sync_chunk_record_decode_count.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn native_sync_chunk_receive_retained_bytes(&self, peer_id: PeerId) -> usize {
        self.sync_chunk_sessions
            .lock()
            .receive
            .get(&peer_id)
            .map(|session| session.retained_len)
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn expire_native_sync_chunk_receive_for_test(&self, peer_id: PeerId) {
        if let Some(session) = self.sync_chunk_sessions.lock().receive.get_mut(&peer_id) {
            let expired_at = Instant::now()
                .checked_sub(NATIVE_SYNC_CHUNK_SESSION_TTL)
                .unwrap_or(session.last_activity_at);
            session.last_activity_at = expired_at;
        }
    }

    fn cooldown_native_sync_chunk_request(&self, completed: NativeCompletedSyncRequest) {
        let mut requests = self.outbound_sync_requests.lock();
        if let Some(request) = requests.get_mut(&completed.request_target) {
            let transition = evaluate_native_sync_chunk_outbound_transition(
                NativeSyncChunkOutboundTransitionInput {
                    state: outbound_chunk_state(request.state),
                    event: NativeSyncChunkOutboundEvent::Abort,
                },
            );
            if request.range == completed.range
                && request.context == completed.context
                && transition == Ok(NativeSyncChunkOutboundState::Cooldown)
            {
                request.state = NativeOutboundSyncRequestState::Cooldown;
                request.requested_at = Instant::now();
            }
        }
    }

    fn finish_native_sync_chunk_request(
        &self,
        peer_id: PeerId,
        completed: NativeCompletedSyncRequest,
    ) -> bool {
        let mut requests = self.outbound_sync_requests.lock();
        let Some(request) = requests.get(&completed.request_target) else {
            return false;
        };
        let transition = evaluate_native_sync_chunk_outbound_transition(
            NativeSyncChunkOutboundTransitionInput {
                state: outbound_chunk_state(request.state),
                event: NativeSyncChunkOutboundEvent::Complete,
            },
        );
        if request.range != completed.range
            || request.context != completed.context
            || completed
                .request_target
                .is_some_and(|target| target != peer_id)
            || transition != Ok(NativeSyncChunkOutboundState::Absent)
        {
            return false;
        }
        requests.remove(&completed.request_target);
        true
    }

    pub(crate) fn reserve_completed_native_sync_chunk_record(
        &self,
        completed: NativeCompletedSyncRequest,
        bytes: &mut Vec<u8>,
        retained_len: usize,
    ) -> Result<()> {
        if let Err(err) = bytes.try_reserve_exact(retained_len) {
            self.cooldown_native_sync_chunk_request(completed);
            return Err(anyhow!("reserve completed native sync chunk record: {err}"));
        }
        Ok(())
    }

    pub(crate) fn prune_native_sync_chunk_sessions(&self) {
        let now = Instant::now();
        let expired_receive = {
            let mut sessions = self.sync_chunk_sessions.lock();
            sessions.serve.retain(|_, session| {
                let (started_at, last_activity_at) = session.timestamps();
                native_sync_chunk_session_is_live(started_at, last_activity_at, now)
            });
            let expired = sessions
                .receive
                .iter()
                .filter_map(|(peer_id, session)| {
                    (!native_sync_chunk_session_is_live(
                        session.started_at,
                        session.last_activity_at,
                        now,
                    ))
                    .then_some((*peer_id, session.completed_request))
                })
                .collect::<Vec<_>>();
            for (peer_id, _) in &expired {
                sessions.receive.remove(peer_id);
            }
            expired
        };
        for (_, completed) in expired_receive {
            self.cooldown_native_sync_chunk_request(completed);
        }
    }

    pub(crate) fn abort_native_sync_chunk_receive(&self, peer_id: PeerId) {
        let completed = self
            .sync_chunk_sessions
            .lock()
            .receive
            .remove(&peer_id)
            .map(|session| session.completed_request);
        if let Some(completed) = completed {
            self.cooldown_native_sync_chunk_request(completed);
        }
    }

    pub(crate) fn begin_native_sync_chunk_receive(
        &self,
        peer_id: PeerId,
        peer_best_height: u64,
        response_empty: bool,
    ) -> Result<NativeSyncBlockChunkRequest> {
        self.prune_native_sync_chunk_sessions();
        let now = Instant::now();
        let mut requests = self.outbound_sync_requests.lock();
        let request_target = [Some(peer_id), None].into_iter().find(|target| {
            requests
                .get(target)
                .is_some_and(|request| request.state == NativeOutboundSyncRequestState::InFlight)
        });
        let requested_from_height = request_target
            .and_then(|target| requests.get(&target))
            .map(|request| request.range.from_height)
            .unwrap_or_default();
        evaluate_native_sync_chunk_fallback_admission(NativeSyncChunkFallbackAdmissionInput {
            matching_completed_request: request_target.is_some(),
            response_empty,
            peer_best_height,
            requested_from_height,
        })
        .map_err(|rejection| {
            anyhow!(
                "native sync chunk fallback admission: {}",
                rejection.label()
            )
        })?;
        let request_target = request_target.expect("fallback admission requires a request");
        let request = *requests
            .get(&request_target)
            .expect("matched native sync request exists");
        let transition = evaluate_native_sync_chunk_outbound_transition(
            NativeSyncChunkOutboundTransitionInput {
                state: outbound_chunk_state(request.state),
                event: NativeSyncChunkOutboundEvent::AdmittedEmptyResponse,
            },
        )
        .map_err(|rejection| anyhow!("native sync chunk transition: {}", rejection.label()))?;
        if transition != NativeSyncChunkOutboundState::ChunkFallback {
            return Err(anyhow!(
                "native sync chunk fallback transition did not enter fallback"
            ));
        }
        let completed_request = NativeCompletedSyncRequest {
            request_target,
            range: request.range,
            context: request.context,
        };
        let expected_height = request.range.from_height;
        let initial_hash = request
            .context
            .target_tip
            .and_then(|(height, hash)| (height == expected_height).then_some(hash));

        let mut sessions = self.sync_chunk_sessions.lock();
        if sessions.receive.contains_key(&peer_id) {
            return Err(anyhow!(
                "native sync chunk receive session already active for peer"
            ));
        }
        evaluate_native_sync_chunk_session_capacity(NativeSyncChunkSessionCapacityInput {
            current_sessions: sessions.len(),
            max_sessions: MAX_NATIVE_SYNC_CHUNK_SESSIONS,
        })
        .map_err(|rejection| {
            anyhow!("native sync chunk receive capacity: {}", rejection.label())
        })?;

        let request_state = requests
            .get_mut(&request_target)
            .expect("matched native sync request still exists");
        request_state.state = NativeOutboundSyncRequestState::ChunkFallback;
        request_state.requested_at = now;
        sessions.receive.insert(
            peer_id,
            NativeSyncChunkReceiveSession {
                peer_best_height,
                expected_height,
                completed_request,
                block_hash: initial_hash,
                record_encoding: None,
                record_digest: None,
                total_len: None,
                retained_len: 0,
                chunks: Vec::new(),
                started_at: now,
                last_activity_at: now,
            },
        );
        Ok(NativeSyncBlockChunkRequest {
            height: expected_height,
            block_hash: initial_hash,
            record_digest: None,
            offset: 0,
        })
    }

    pub(crate) fn ingest_native_sync_block_chunk(
        &self,
        peer_id: PeerId,
        chunk: NativeSyncBlockChunk,
    ) -> Result<NativeSyncChunkReceiveProgress> {
        let outcome = self.ingest_native_sync_block_chunk_inner(peer_id, chunk);
        if outcome.is_err() {
            self.abort_native_sync_chunk_receive(peer_id);
        }
        outcome
    }

    /// Allocation-free admission on the async receive loop before a bounded
    /// blocking worker is dispatched. The worker repeats this gate before any
    /// session mutation.
    pub(crate) fn preflight_native_sync_block_chunk(
        &self,
        peer_id: PeerId,
        chunk: &NativeSyncBlockChunk,
    ) -> Result<()> {
        let now = Instant::now();
        let sessions = self.sync_chunk_sessions.lock();
        let session = sessions
            .receive
            .get(&peer_id)
            .ok_or_else(|| anyhow!("unsolicited native sync block chunk"))?;
        evaluate_native_sync_chunk_session_expiry(native_sync_chunk_expiry_input(
            session.started_at,
            session.last_activity_at,
            now,
        ))
        .map_err(|rejection| {
            anyhow!("native sync chunk preflight expiry: {}", rejection.label())
        })?;
        let supported_encoding = matches!(
            chunk.record_encoding,
            NATIVE_SYNC_CHUNK_RECORD_ENCODING_LEGACY_V1
                | NATIVE_SYNC_CHUNK_RECORD_ENCODING_CURRENT_V2
        );
        let session_matches = supported_encoding
            && session.expected_height == chunk.height
            && chunk.best_height >= chunk.height
            && session
                .block_hash
                .is_none_or(|expected| expected == chunk.block_hash)
            && session
                .record_encoding
                .is_none_or(|expected| expected == chunk.record_encoding)
            && session
                .record_digest
                .is_none_or(|expected| expected == chunk.record_digest)
            && session
                .total_len
                .is_none_or(|expected| expected == chunk.total_len);
        evaluate_native_sync_block_chunk_admission(NativeSyncBlockChunkAdmissionInput {
            session_matches,
            chunk_len: chunk.bytes.len(),
            max_chunk_bytes: MAX_NATIVE_SYNC_CHUNK_BYTES,
            total_len: chunk.total_len,
            max_total_len: MAX_NATIVE_BLOCK_META_BYTES as u64,
            offset: chunk.offset,
            retained_len: session.retained_len,
        })
        .map_err(|rejection| anyhow!("native sync block chunk preflight: {}", rejection.label()))
    }

    /// Authenticated, allocation-free server-side gate used before consuming
    /// a response-worker slot or dispatching storage work.
    pub(crate) fn preflight_native_sync_chunk_serve_request(
        &self,
        peer_id: PeerId,
        request: &NativeSyncBlockChunkRequest,
    ) -> Result<NativeSyncChunkServeRequestDisposition> {
        let now = Instant::now();
        let sessions = self.sync_chunk_sessions.lock();
        let Some(session) = sessions.serve.get(&peer_id) else {
            return evaluate_native_sync_chunk_serve_request_admission(
                NativeSyncChunkServeRequestAdmissionInput {
                    matching_live_offer_or_session: false,
                    tuple_matches: false,
                    offset: request.offset,
                    next_offset: 0,
                    total_len: 0,
                },
            )
            .map_err(|rejection| {
                anyhow!("native sync chunk serve preflight: {}", rejection.label())
            });
        };
        let (started_at, last_activity_at) = session.timestamps();
        evaluate_native_sync_chunk_session_expiry(native_sync_chunk_expiry_input(
            started_at,
            last_activity_at,
            now,
        ))
        .map_err(|rejection| {
            anyhow!(
                "native sync chunk serve preflight expiry: {}",
                rejection.label()
            )
        })?;
        let disposition = match session {
            NativeSyncChunkServeSession::Offered { range, offer, .. } => {
                evaluate_native_sync_chunk_offer_request_admission(
                    NativeSyncChunkOfferRequestAdmissionInput {
                        matching_live_offer: true,
                        height_matches: request.height == range.from_height
                            && request.height == offer.height,
                        block_hash_matches: request
                            .block_hash
                            .is_none_or(|hash| hash == offer.block_hash),
                        record_digest_absent: request.record_digest.is_none(),
                        offset: request.offset,
                    },
                )
                .map_err(|rejection| {
                    anyhow!("native sync chunk offer preflight: {}", rejection.label())
                })?;
                evaluate_native_sync_chunk_serve_request_admission(
                    NativeSyncChunkServeRequestAdmissionInput {
                        matching_live_offer_or_session: true,
                        tuple_matches: true,
                        offset: request.offset,
                        next_offset: 0,
                        total_len: u64::MAX,
                    },
                )
            }
            NativeSyncChunkServeSession::Loading { .. } => {
                Err(NativeSyncChunkAdmissionRejection::SessionMismatch)
            }
            NativeSyncChunkServeSession::Serving {
                range,
                offer,
                record_digest,
                record,
                next_offset,
                ..
            } => {
                let total_len = u64::try_from(record.len())
                    .map_err(|_| anyhow!("native sync chunk record length overflow"))?;
                let initial_request = request.offset == 0
                    && *next_offset == 0
                    && request
                        .block_hash
                        .is_none_or(|hash| hash == offer.block_hash)
                    && request
                        .record_digest
                        .is_none_or(|digest| digest == *record_digest);
                let bound_request = request.block_hash == Some(offer.block_hash)
                    && request.record_digest == Some(*record_digest);
                evaluate_native_sync_chunk_serve_request_admission(
                    NativeSyncChunkServeRequestAdmissionInput {
                        matching_live_offer_or_session: true,
                        tuple_matches: request.height == range.from_height
                            && request.height == offer.height
                            && (initial_request || bound_request),
                        offset: request.offset,
                        next_offset: *next_offset,
                        total_len,
                    },
                )
            }
        }
        .map_err(|rejection| anyhow!("native sync chunk serve preflight: {}", rejection.label()))?;
        if matches!(session, NativeSyncChunkServeSession::Offered { .. })
            && disposition != NativeSyncChunkServeRequestDisposition::ServeNext
        {
            return Err(anyhow!(
                "native sync chunk offer cannot close before record load"
            ));
        }
        Ok(disposition)
    }

    fn ingest_native_sync_block_chunk_inner(
        &self,
        peer_id: PeerId,
        chunk: NativeSyncBlockChunk,
    ) -> Result<NativeSyncChunkReceiveProgress> {
        let now = Instant::now();
        let completed = {
            let mut sessions = self.sync_chunk_sessions.lock();
            let session = sessions
                .receive
                .get_mut(&peer_id)
                .ok_or_else(|| anyhow!("unsolicited native sync block chunk"))?;
            evaluate_native_sync_chunk_session_expiry(native_sync_chunk_expiry_input(
                session.started_at,
                session.last_activity_at,
                now,
            ))
            .map_err(|rejection| {
                anyhow!("native sync chunk receive expiry: {}", rejection.label())
            })?;

            let supported_encoding = matches!(
                chunk.record_encoding,
                NATIVE_SYNC_CHUNK_RECORD_ENCODING_LEGACY_V1
                    | NATIVE_SYNC_CHUNK_RECORD_ENCODING_CURRENT_V2
            );
            let session_matches = supported_encoding
                && session.expected_height == chunk.height
                && chunk.best_height >= chunk.height
                && session
                    .block_hash
                    .is_none_or(|expected| expected == chunk.block_hash)
                && session
                    .record_encoding
                    .is_none_or(|expected| expected == chunk.record_encoding)
                && session
                    .record_digest
                    .is_none_or(|expected| expected == chunk.record_digest)
                && session
                    .total_len
                    .is_none_or(|expected| expected == chunk.total_len);
            evaluate_native_sync_block_chunk_admission(NativeSyncBlockChunkAdmissionInput {
                session_matches,
                chunk_len: chunk.bytes.len(),
                max_chunk_bytes: MAX_NATIVE_SYNC_CHUNK_BYTES,
                total_len: chunk.total_len,
                max_total_len: MAX_NATIVE_BLOCK_META_BYTES as u64,
                offset: chunk.offset,
                retained_len: session.retained_len,
            })
            .map_err(|rejection| {
                anyhow!("native sync block chunk admission: {}", rejection.label())
            })?;

            session.block_hash = Some(chunk.block_hash);
            session.record_encoding = Some(chunk.record_encoding);
            session.record_digest = Some(chunk.record_digest);
            session.total_len = Some(chunk.total_len);
            // Move the admitted wire allocation into a segment. This avoids
            // repeatedly reallocating and copying the full retained prefix.
            session.retained_len = session
                .retained_len
                .checked_add(chunk.bytes.len())
                .ok_or_else(|| anyhow!("native sync chunk retained length overflow"))?;
            session.chunks.push(chunk.bytes);
            session.last_activity_at = now;
            if u64::try_from(session.retained_len).ok() != Some(chunk.total_len) {
                return Ok(NativeSyncChunkReceiveProgress::NeedMore(
                    NativeSyncBlockChunkRequest {
                        height: session.expected_height,
                        block_hash: session.block_hash,
                        record_digest: session.record_digest,
                        offset: u64::try_from(session.retained_len)
                            .map_err(|_| anyhow!("native sync chunk receive offset overflow"))?,
                    },
                ));
            }
            let session = sessions
                .receive
                .remove(&peer_id)
                .expect("completed native sync chunk receive session exists");
            (
                session.peer_best_height,
                session.completed_request,
                session.block_hash.expect("chunk hash established"),
                session.record_encoding.expect("chunk encoding established"),
                session.record_digest.expect("chunk digest established"),
                session.total_len.expect("chunk total established"),
                session.retained_len,
                session.chunks,
            )
        };

        let (
            peer_best_height,
            completed_request,
            block_hash,
            record_encoding,
            record_digest,
            total_len,
            retained_len,
            chunks,
        ) = completed;
        let mut bytes = Vec::new();
        self.reserve_completed_native_sync_chunk_record(
            completed_request,
            &mut bytes,
            retained_len,
        )?;
        for segment in chunks {
            bytes.extend_from_slice(&segment);
        }
        debug_assert_eq!(bytes.len(), retained_len);
        let digest_matches = native_sync_chunk_record_digest(
            record_encoding,
            completed_request.range.from_height,
            block_hash,
            total_len,
            &bytes,
        ) == record_digest;
        let assembled_len = bytes.len();
        if !digest_matches {
            drop(bytes);
            self.cooldown_native_sync_chunk_request(completed_request);
            return Err(anyhow!(
                "native sync block chunk completion: {}",
                NativeSyncChunkAdmissionRejection::RecordDigestMismatch.label()
            ));
        }
        #[cfg(test)]
        self.sync_chunk_record_decode_count
            .fetch_add(1, Ordering::Relaxed);
        let decoded = decode_native_sync_chunk_record_exact(record_encoding, &bytes);
        // The exact decoder currently materializes a decoded record and a
        // transient canonical re-encoding. Release the assembled raw bytes as
        // soon as that check returns, before common import/reorg preparation.
        drop(bytes);
        let exact_decode_accepts = decoded.is_ok();
        let height_matches = decoded
            .as_ref()
            .is_ok_and(|block| block.height == completed_request.range.from_height);
        let hash_matches = decoded
            .as_ref()
            .is_ok_and(|block| block.hash == block_hash && block.work_hash == block_hash);
        let request_prefix_matches = decoded.as_ref().is_ok_and(|block| {
            native_sync_response_is_contiguous_request_prefix(
                completed_request.range,
                std::slice::from_ref(block),
            )
        });
        let recovery_context_matches = decoded.as_ref().is_ok_and(|block| {
            native_sync_response_matches_recovery_context(
                completed_request.context.expected_parent_hash,
                completed_request.context.target_tip,
                std::slice::from_ref(block),
            )
        });
        if let Err(rejection) = evaluate_native_sync_block_chunk_completion_admission(
            NativeSyncBlockChunkCompletionAdmissionInput {
                assembled_len,
                total_len,
                digest_matches,
                exact_decode_accepts,
                height_matches,
                hash_matches,
                request_prefix_matches,
                recovery_context_matches,
            },
        ) {
            self.cooldown_native_sync_chunk_request(completed_request);
            return Err(anyhow!(
                "native sync block chunk completion: {}",
                rejection.label()
            ));
        }
        let block = decoded.expect("completion admission requires exact decoded block");
        if !self.finish_native_sync_chunk_request(peer_id, completed_request) {
            self.cooldown_native_sync_chunk_request(completed_request);
            return Err(anyhow!(
                "native sync chunk completion lost its authorized request"
            ));
        }
        Ok(NativeSyncChunkReceiveProgress::Complete {
            peer_best_height,
            completed_request,
            block: Box::new(block),
            close_request: NativeSyncBlockChunkRequest {
                height: completed_request.range.from_height,
                block_hash: Some(block_hash),
                record_digest: Some(record_digest),
                offset: total_len,
            },
        })
    }

    pub(crate) fn offer_native_sync_block_chunk(
        &self,
        peer_id: PeerId,
        range: NativeSyncRange,
        offer: NativeSyncChunkOffer,
    ) -> Result<()> {
        self.prune_native_sync_chunk_sessions();
        if range.from_height != offer.height {
            return Err(anyhow!(
                "native sync chunk offer must be the requested range prefix"
            ));
        }
        let now = Instant::now();
        let mut sessions = self.sync_chunk_sessions.lock();
        if sessions.serve.contains_key(&peer_id) {
            return Err(anyhow!(
                "native sync chunk serve session already active for peer"
            ));
        }
        evaluate_native_sync_chunk_session_capacity(NativeSyncChunkSessionCapacityInput {
            current_sessions: sessions.len(),
            max_sessions: MAX_NATIVE_SYNC_CHUNK_SESSIONS,
        })
        .map_err(|rejection| anyhow!("native sync chunk offer capacity: {}", rejection.label()))?;
        sessions.serve.insert(
            peer_id,
            NativeSyncChunkServeSession::Offered {
                range,
                offer,
                started_at: now,
                last_activity_at: now,
            },
        );
        Ok(())
    }

    pub(crate) fn remove_native_sync_chunk_serve_session(&self, peer_id: PeerId) {
        self.sync_chunk_sessions.lock().serve.remove(&peer_id);
    }

    fn load_native_sync_chunk_record(
        &self,
        offer: NativeSyncChunkOffer,
    ) -> Result<(u8, [u8; 32], sled::IVec)> {
        #[cfg(test)]
        self.sync_chunk_record_load_count
            .fetch_add(1, Ordering::Relaxed);
        let indexed_hash = self
            .hash_by_height(offer.height)?
            .ok_or_else(|| anyhow!("missing canonical native sync chunk height"))?;
        if indexed_hash != offer.block_hash {
            return Err(anyhow!("native sync chunk offer is no longer canonical"));
        }
        let record = self
            .block_tree
            .get(offer.block_hash.as_slice())?
            .ok_or_else(|| anyhow!("missing canonical native sync chunk block record"))?;
        if record.is_empty() || record.len() > MAX_NATIVE_BLOCK_META_BYTES {
            return Err(anyhow!(
                "native sync chunk block record length out of bounds: {}",
                record.len()
            ));
        }
        let (meta, record_encoding) = detect_bincode_native_block_meta_schema_exact(
            record.as_ref(),
            "native sync chunk canonical block record",
        )?;
        if meta.height != offer.height
            || meta.hash != offer.block_hash
            || meta.work_hash != offer.block_hash
        {
            return Err(anyhow!(
                "native sync chunk record does not match its canonical offer"
            ));
        }
        self.validate_canonical_sync_block_meta(&meta)?;
        drop(meta);
        if self.hash_by_height(offer.height)? != Some(offer.block_hash) {
            return Err(anyhow!(
                "native sync chunk canonical index changed during preparation"
            ));
        }
        let total_len = u64::try_from(record.len())
            .map_err(|_| anyhow!("native sync chunk record length overflow"))?;
        let record_digest = native_sync_chunk_record_digest(
            record_encoding,
            offer.height,
            offer.block_hash,
            total_len,
            record.as_ref(),
        );
        Ok((record_encoding, record_digest, record))
    }

    pub(crate) fn native_sync_block_chunk_for_request(
        &self,
        peer_id: PeerId,
        request: NativeSyncBlockChunkRequest,
    ) -> Result<Option<NativeSyncBlockChunk>> {
        self.prune_native_sync_chunk_sessions();
        let now = Instant::now();
        let load = {
            let mut sessions = self.sync_chunk_sessions.lock();
            let Some(session) = sessions.serve.get_mut(&peer_id) else {
                evaluate_native_sync_chunk_serve_request_admission(
                    NativeSyncChunkServeRequestAdmissionInput {
                        matching_live_offer_or_session: false,
                        tuple_matches: false,
                        offset: request.offset,
                        next_offset: 0,
                        total_len: 0,
                    },
                )
                .map_err(|rejection| {
                    anyhow!("native sync chunk serve request: {}", rejection.label())
                })?;
                unreachable!("missing offer is always rejected")
            };
            let (started_at, last_activity_at) = session.timestamps();
            evaluate_native_sync_chunk_session_expiry(native_sync_chunk_expiry_input(
                started_at,
                last_activity_at,
                now,
            ))
            .map_err(|rejection| {
                anyhow!("native sync chunk serve expiry: {}", rejection.label())
            })?;
            match session {
                NativeSyncChunkServeSession::Offered {
                    range,
                    offer,
                    started_at,
                    ..
                } => {
                    evaluate_native_sync_chunk_offer_request_admission(
                        NativeSyncChunkOfferRequestAdmissionInput {
                            matching_live_offer: true,
                            height_matches: request.height == range.from_height
                                && request.height == offer.height,
                            block_hash_matches: request
                                .block_hash
                                .is_none_or(|hash| hash == offer.block_hash),
                            record_digest_absent: request.record_digest.is_none(),
                            offset: request.offset,
                        },
                    )
                    .map_err(|rejection| {
                        anyhow!("native sync chunk offer request: {}", rejection.label())
                    })?;
                    let disposition = evaluate_native_sync_chunk_serve_request_admission(
                        NativeSyncChunkServeRequestAdmissionInput {
                            matching_live_offer_or_session: true,
                            tuple_matches: true,
                            offset: request.offset,
                            next_offset: 0,
                            total_len: u64::MAX,
                        },
                    )
                    .map_err(|rejection| {
                        anyhow!("native sync chunk offer request: {}", rejection.label())
                    })?;
                    if disposition != NativeSyncChunkServeRequestDisposition::ServeNext {
                        return Err(anyhow!(
                            "native sync chunk offer cannot close before record load"
                        ));
                    }
                    let range = *range;
                    let offer = *offer;
                    let started_at = *started_at;
                    *session = NativeSyncChunkServeSession::Loading {
                        range,
                        offer,
                        started_at,
                        last_activity_at: now,
                    };
                    Some((range, offer, started_at))
                }
                NativeSyncChunkServeSession::Loading { .. } => {
                    return Err(anyhow!("native sync chunk record load already active"));
                }
                NativeSyncChunkServeSession::Serving { .. } => None,
            }
        };

        if let Some((range, offer, started_at)) = load {
            let loaded = self.load_native_sync_chunk_record(offer);
            let (record_encoding, record_digest, record) = match loaded {
                Ok(loaded) => loaded,
                Err(err) => {
                    self.remove_native_sync_chunk_serve_session(peer_id);
                    return Err(err);
                }
            };
            let now = Instant::now();
            let mut sessions = self.sync_chunk_sessions.lock();
            let session = sessions
                .serve
                .get_mut(&peer_id)
                .ok_or_else(|| anyhow!("native sync chunk offer expired during record load"))?;
            let exact_loading = matches!(
                session,
                NativeSyncChunkServeSession::Loading {
                    range: current_range,
                    offer: current_offer,
                    started_at: current_started,
                    ..
                } if *current_range == range && *current_offer == offer && *current_started == started_at
            );
            let (_, last_activity_at) = session.timestamps();
            evaluate_native_sync_chunk_session_expiry(native_sync_chunk_expiry_input(
                started_at,
                last_activity_at,
                now,
            ))
            .map_err(|rejection| {
                anyhow!(
                    "native sync chunk load completion expiry: {}",
                    rejection.label()
                )
            })?;
            if !exact_loading {
                return Err(anyhow!(
                    "native sync chunk offer changed during record load"
                ));
            }
            *session = NativeSyncChunkServeSession::Serving {
                range,
                offer,
                record_encoding,
                record_digest,
                record,
                next_offset: 0,
                started_at,
                last_activity_at: now,
            };
        }

        let canonical_hash = self.hash_by_height(request.height)?;
        let now = Instant::now();
        let (chunk, close) = {
            let mut sessions = self.sync_chunk_sessions.lock();
            let session = sessions
                .serve
                .get_mut(&peer_id)
                .ok_or_else(|| anyhow!("native sync chunk serving session disappeared"))?;
            let NativeSyncChunkServeSession::Serving {
                range,
                offer,
                record_encoding,
                record_digest,
                record,
                next_offset,
                started_at,
                last_activity_at,
            } = session
            else {
                return Err(anyhow!("native sync chunk serving session is not ready"));
            };
            if canonical_hash != Some(offer.block_hash) {
                return Err(anyhow!(
                    "native sync chunk canonical index changed before serving"
                ));
            }
            evaluate_native_sync_chunk_session_expiry(native_sync_chunk_expiry_input(
                *started_at,
                *last_activity_at,
                now,
            ))
            .map_err(|rejection| {
                anyhow!("native sync chunk serve expiry: {}", rejection.label())
            })?;
            let total_len = u64::try_from(record.len())
                .map_err(|_| anyhow!("native sync chunk record length overflow"))?;
            let initial_request = request.offset == 0
                && *next_offset == 0
                && request
                    .block_hash
                    .is_none_or(|hash| hash == offer.block_hash)
                && request
                    .record_digest
                    .is_none_or(|digest| digest == *record_digest);
            let bound_request = request.block_hash == Some(offer.block_hash)
                && request.record_digest == Some(*record_digest);
            let tuple_matches = request.height == range.from_height
                && request.height == offer.height
                && (initial_request || bound_request);
            let disposition = evaluate_native_sync_chunk_serve_request_admission(
                NativeSyncChunkServeRequestAdmissionInput {
                    matching_live_offer_or_session: true,
                    tuple_matches,
                    offset: request.offset,
                    next_offset: *next_offset,
                    total_len,
                },
            )
            .map_err(|rejection| {
                anyhow!("native sync chunk serving request: {}", rejection.label())
            })?;
            match disposition {
                NativeSyncChunkServeRequestDisposition::Close => (None, true),
                NativeSyncChunkServeRequestDisposition::ServeNext => {
                    let offset = usize::try_from(request.offset)
                        .map_err(|_| anyhow!("native sync chunk request offset overflow"))?;
                    if offset >= record.len() {
                        return Err(anyhow!("native sync chunk request offset past record"));
                    }
                    let end = offset
                        .saturating_add(MAX_NATIVE_SYNC_CHUNK_BYTES)
                        .min(record.len());
                    let bytes = record[offset..end].to_vec();
                    *next_offset = u64::try_from(end)
                        .map_err(|_| anyhow!("native sync chunk next offset overflow"))?;
                    *last_activity_at = now;
                    (
                        Some(NativeSyncBlockChunk {
                            best_height: self.best_height(),
                            height: offer.height,
                            block_hash: offer.block_hash,
                            record_encoding: *record_encoding,
                            record_digest: *record_digest,
                            total_len,
                            offset: request.offset,
                            bytes,
                        }),
                        false,
                    )
                }
            }
        };
        if close {
            self.remove_native_sync_chunk_serve_session(peer_id);
        }
        Ok(chunk)
    }
}
