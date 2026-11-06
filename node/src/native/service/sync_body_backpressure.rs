// Preserve admitted body work when its control frame cannot enter the local queue.

use super::*;

impl NativeBlockBodyTransport {
    /// Roll back only the exact, still-unsent body request just admitted locally.
    ///
    /// This is local queue pressure, not a failed peer response. Retain the same
    /// queue slot, retry budget and absolute deadline, and release only this
    /// request's unprogressed reassembly reservation. Call synchronously after a
    /// failed nonblocking send, before processing another transport event.
    pub(super) fn defer_unsent_body_request(
        &mut self,
        peer_id: PeerId,
        expected: &NativeBlockBodyLocator,
    ) -> bool {
        let Some(queue) = self.peers.get_mut(&peer_id) else {
            return false;
        };
        let Some(active) = queue.active.as_ref() else {
            return false;
        };
        if active.locator != *expected {
            return false;
        }
        let key = (peer_id, expected.block_hash);
        let Some(assembly) = self.reassembler.entries.get(&key) else {
            return false;
        };
        if assembly.locator != *expected
            || Some(assembly.started_at) != active.started_at
            || assembly.received_chunks != 0
            || assembly.received_bytes != 0
        {
            return false;
        }
        // Move an existing item rather than reserving another slot. Neither
        // per-peer/global queue counts nor their configured limits change.
        let active = queue.active.take().expect("matched unsent body exists");
        self.reassembler.remove(&key);
        queue.waiting.push_front(active);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator(seed: u8, total_len: usize) -> NativeBlockBodyLocator {
        NativeBlockBodyLocator {
            schema_version: NATIVE_BLOCK_BODY_SCHEMA_VERSION,
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
            height: u64::from(seed),
            block_hash: [seed; 32],
            parent_hash: [seed.wrapping_sub(1); 32],
            cumulative_work: [0; 48],
            total_len: total_len as u64,
            body_hash: [seed; 32],
            chunk_count: native_block_body_chunk_count(total_len).unwrap(),
        }
    }

    fn assert_conserved(transport: &NativeBlockBodyTransport) {
        let queued = transport
            .peers
            .values()
            .map(|queue| queue.waiting.len() + usize::from(queue.active.is_some()))
            .sum::<usize>();
        assert_eq!(transport.queued_bodies, queued);
        assert!(queued <= MAX_NATIVE_BLOCK_BODY_QUEUE_GLOBAL);
        for queue in transport.peers.values() {
            assert!(
                queue.waiting.len() + usize::from(queue.active.is_some())
                    <= MAX_NATIVE_BLOCK_BODY_QUEUE_PER_PEER
            );
        }
        let reserved = transport
            .reassembler
            .entries
            .values()
            .map(|entry| entry.locator.total_len as usize)
            .sum::<usize>();
        assert_eq!(transport.reassembler.reserved_bytes, reserved);
        assert!(reserved <= MAX_NATIVE_BLOCK_BODY_REASSEMBLY_RESERVED_BYTES);
        assert!(transport.reassembler.entries.len() <= MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL);
        for peer in transport.peers.keys() {
            assert!(
                transport
                    .reassembler
                    .entries
                    .keys()
                    .filter(|(entry_peer, _)| entry_peer == peer)
                    .count()
                    <= MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_PER_PEER
            );
        }
    }

    #[test]
    fn body_local_full_preserves_range_origin_retry_age_suffix_and_other_reservations() {
        let now = Instant::now();
        let peer = [0x81; 32];
        let other = [0x82; 32];
        let first = locator(20, 7);
        let next = locator(21, 9);
        let range = NativeSyncRange {
            from_height: 20,
            to_height: 21,
        };
        let completed_request = NativeCompletedSyncRequest {
            request_target: Some(peer),
            range,
            context: NativeOutboundSyncRequestContext::default(),
        };
        let mut transport = NativeBlockBodyTransport::default();
        transport
            .enqueue_range(
                peer,
                22,
                vec![first.clone(), next.clone()],
                completed_request,
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            transport.start_next(peer, now).unwrap(),
            Some(first.clone())
        );
        // Exercise the real peer timeout once before local send pressure. Local
        // rejection must preserve that already-consumed network retry budget.
        let retry_at = now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL;
        assert_eq!(transport.expire_and_retry(retry_at).requests.len(), 1);
        let before = transport.peers[&peer].active.clone().unwrap();
        assert_eq!(before.retries, 1);
        transport.enqueue_announce(other, locator(30, 11)).unwrap();
        transport.start_next(other, retry_at).unwrap().unwrap();
        let queued_before = transport.queued_bodies;
        let reserved_before = transport.reassembler.reserved_bytes;

        assert!(transport.defer_unsent_body_request(peer, &first));
        assert!(!transport.defer_unsent_body_request(peer, &first));
        let queue = &transport.peers[&peer];
        assert!(queue.active.is_none());
        assert_eq!(queue.waiting.len(), 2);
        let deferred = &queue.waiting[0];
        assert_eq!(deferred.locator, before.locator);
        assert_eq!(deferred.retries, before.retries);
        assert_eq!(deferred.started_at, before.started_at);
        match deferred.origin {
            NativeQueuedBlockBodyOrigin::Range {
                best_height,
                response_range,
                final_pending_body,
                response_tip_hash,
                completed_request: origin_request,
            } => assert_eq!(
                (
                    best_height,
                    response_range,
                    final_pending_body,
                    response_tip_hash,
                    origin_request,
                ),
                (22, range, false, Some(first.block_hash), completed_request)
            ),
            NativeQueuedBlockBodyOrigin::Announce => panic!("range origin must be retained"),
        }
        assert_eq!(queue.waiting[1].locator, next);
        assert_eq!(transport.queued_bodies, queued_before);
        assert_eq!(transport.reassembler.reserved_bytes, reserved_before - 7);
        assert!(transport.reassembler.contains(other, [30; 32]));
        assert_conserved(&transport);

        let admitted = transport.expire_and_retry(retry_at + Duration::from_secs(1));
        assert_eq!(admitted.requests, vec![(peer, first)]);
        let active = transport.peers[&peer].active.as_ref().unwrap();
        assert_eq!(active.retries, 1);
        assert_eq!(active.started_at, Some(now));
        assert_conserved(&transport);
    }

    #[test]
    fn body_local_full_stale_callback_cannot_remove_newer_locator_with_same_hash() {
        let now = Instant::now();
        let peer = [0x83; 32];
        let first = locator(40, 1);
        let mut transport = NativeBlockBodyTransport::default();
        transport.enqueue_announce(peer, first.clone()).unwrap();
        transport.start_next(peer, now).unwrap().unwrap();
        transport
            .push_chunk(
                peer,
                native_block_body_chunk(&first, &[40], 0).unwrap(),
                now,
            )
            .unwrap()
            .unwrap();
        let mut newer = first.clone();
        newer.total_len = 2;
        newer.body_hash = [0x99; 32];
        transport.enqueue_announce(peer, newer.clone()).unwrap();
        transport.start_next(peer, now).unwrap().unwrap();

        assert!(!transport.defer_unsent_body_request(peer, &first));
        assert!(!transport.defer_unsent_body_request([0x84; 32], &newer));
        assert_eq!(
            transport.peers[&peer].active.as_ref().unwrap().locator,
            newer
        );
        assert_eq!(transport.reassembler.reserved_bytes, 2);
        assert_eq!(
            transport.reassembler.entries[&(peer, first.block_hash)].locator,
            newer
        );
        assert_conserved(&transport);
    }

    #[test]
    fn body_local_full_cannot_abort_progress_or_another_reservation_epoch() {
        let now = Instant::now();
        let peer = [0x85; 32];
        let next = locator(50, MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES + 1);
        let mut transport = NativeBlockBodyTransport::default();
        transport.enqueue_announce(peer, next.clone()).unwrap();
        transport.start_next(peer, now).unwrap().unwrap();
        let bytes = vec![50; MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES + 1];
        let chunk = native_block_body_chunk(&next, &bytes, 0).unwrap();
        assert!(transport.push_chunk(peer, chunk, now).unwrap().is_none());
        assert!(!transport.defer_unsent_body_request(peer, &next));
        assert_conserved(&transport);

        transport.abort_peer(peer);
        transport.enqueue_announce(peer, next.clone()).unwrap();
        transport.start_next(peer, now).unwrap().unwrap();
        transport
            .reassembler
            .entries
            .get_mut(&(peer, next.block_hash))
            .unwrap()
            .started_at = now + Duration::from_secs(1);
        assert!(!transport.defer_unsent_body_request(peer, &next));
        assert!(transport.peers[&peer].active.is_some());
        assert_conserved(&transport);
    }

    #[test]
    fn body_local_full_eventually_readmits_after_global_item_and_byte_capacity_frees() {
        let now = Instant::now();
        let peer = [0x86; 32];
        let next = locator(60, MAX_NATIVE_BLOCK_META_BYTES);
        let mut transport = NativeBlockBodyTransport::default();
        transport.enqueue_announce(peer, next.clone()).unwrap();
        transport.start_next(peer, now).unwrap().unwrap();
        assert!(transport.defer_unsent_body_request(peer, &next));
        for index in 0..MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL {
            let other = [index as u8; 32];
            transport
                .enqueue_announce(other, locator(index as u8, MAX_NATIVE_BLOCK_META_BYTES))
                .unwrap();
            transport.start_next(other, now).unwrap().unwrap();
        }
        assert_eq!(
            transport.reassembler.reserved_bytes,
            MAX_NATIVE_BLOCK_BODY_REASSEMBLY_RESERVED_BYTES
        );
        assert!(transport.start_next(peer, now).is_err());
        assert!(transport
            .expire_and_retry(now + Duration::from_secs(1))
            .requests
            .is_empty());
        assert_eq!(transport.peers[&peer].waiting[0].started_at, Some(now));
        assert_eq!(transport.peers[&peer].waiting[0].retries, 0);
        assert_conserved(&transport);

        transport.abort_peer([0; 32]);
        let admitted = transport.expire_and_retry(now + Duration::from_secs(2));
        assert_eq!(admitted.requests, vec![(peer, next)]);
        assert_conserved(&transport);
    }

    #[test]
    fn body_local_full_moves_existing_slot_at_full_peer_and_global_queue_limits() {
        let now = Instant::now();
        let mut transport = NativeBlockBodyTransport::default();
        let mut first_peer = None;
        for peer_index in 0..MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL {
            let peer = [peer_index as u8; 32];
            let locators = (0..MAX_NATIVE_BLOCK_BODY_QUEUE_PER_PEER)
                .map(|index| {
                    let mut next = locator(index as u8, 1);
                    next.height = index as u64;
                    next
                })
                .collect::<Vec<_>>();
            let range = NativeSyncRange {
                from_height: locators.first().unwrap().height,
                to_height: locators.last().unwrap().height,
            };
            let request = NativeCompletedSyncRequest {
                request_target: Some(peer),
                range,
                context: NativeOutboundSyncRequestContext::default(),
            };
            transport
                .enqueue_range(peer, range.to_height, locators, request)
                .unwrap()
                .unwrap();
            let active = transport.start_next(peer, now).unwrap().unwrap();
            if first_peer.is_none() {
                first_peer = Some((peer, active));
            }
        }
        assert_eq!(transport.queued_bodies, MAX_NATIVE_BLOCK_BODY_QUEUE_GLOBAL);
        let (peer, expected) = first_peer.unwrap();
        assert!(transport.defer_unsent_body_request(peer, &expected));
        assert_eq!(
            transport.peers[&peer].waiting.len(),
            MAX_NATIVE_BLOCK_BODY_QUEUE_PER_PEER
        );
        assert_eq!(transport.queued_bodies, MAX_NATIVE_BLOCK_BODY_QUEUE_GLOBAL);
        assert_conserved(&transport);
        assert_eq!(transport.start_next(peer, now).unwrap(), Some(expected));
        assert_conserved(&transport);
    }

    #[test]
    fn body_local_full_repeated_deferral_cannot_extend_absolute_lifetime() {
        let now = Instant::now();
        let peer = [0x87; 32];
        let next = locator(70, 3);
        let mut transport = NativeBlockBodyTransport::default();
        transport.enqueue_announce(peer, next.clone()).unwrap();
        transport.start_next(peer, now).unwrap().unwrap();
        assert!(transport.defer_unsent_body_request(peer, &next));
        let deadline = now + NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME;
        assert_eq!(
            transport
                .start_next(peer, deadline - Duration::from_secs(1))
                .unwrap(),
            Some(next.clone())
        );
        assert_eq!(transport.peers[&peer].active.as_ref().unwrap().retries, 0);
        assert!(transport.defer_unsent_body_request(peer, &next));
        assert!(transport.start_next(peer, deadline).is_err());
        let expired = transport.expire_and_retry(deadline);
        assert!(expired.requests.is_empty());
        assert_eq!(expired.aborted.len(), 1);
        assert_eq!(expired.aborted[0].0, peer);
        assert_eq!(transport.queued_bodies, 0);
        assert_eq!(transport.reassembler.reserved_bytes, 0);
        assert_conserved(&transport);
    }

    #[test]
    fn body_local_full_rollback_leaves_normal_idle_retry_and_expiry_unchanged() {
        let now = Instant::now();
        let peer = [0x88; 32];
        let next = locator(80, 5);
        let mut transport = NativeBlockBodyTransport::default();
        transport.enqueue_announce(peer, next.clone()).unwrap();
        transport.start_next(peer, now).unwrap().unwrap();
        assert!(transport.defer_unsent_body_request(peer, &next));
        let sent_at = now + Duration::from_secs(1);
        assert_eq!(
            transport.start_next(peer, sent_at).unwrap(),
            Some(next.clone())
        );
        let retried = transport.expire_and_retry(sent_at + NATIVE_BLOCK_BODY_REASSEMBLY_TTL);
        assert_eq!(retried.requests, vec![(peer, next)]);
        assert!(retried.aborted.is_empty());
        assert_eq!(transport.peers[&peer].active.as_ref().unwrap().retries, 1);
        let expired = transport.expire_and_retry(sent_at + NATIVE_BLOCK_BODY_REASSEMBLY_TTL * 2);
        assert!(expired.requests.is_empty());
        assert_eq!(expired.aborted.len(), 1);
        assert_eq!(transport.queued_bodies, 0);
        assert_eq!(transport.reassembler.reserved_bytes, 0);
        assert_conserved(&transport);
    }
}
