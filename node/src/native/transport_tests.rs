use super::*;

use std::sync::Mutex as StdMutex;

static TRANSPORT_COUNTER_TEST_LOCK: StdMutex<()> = StdMutex::new(());

fn sample_meta(seed: u8, action_bytes: Vec<Vec<u8>>) -> NativeBlockMeta {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    let mut parent_hash = [0u8; 32];
    parent_hash[0] = seed.saturating_sub(1);
    let mut cumulative_work = [0u8; 48];
    cumulative_work[47] = seed;
    NativeBlockMeta {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
        height: u64::from(seed),
        hash,
        parent_hash,
        state_root: [seed; 48],
        kernel_root: [seed.wrapping_add(1); 48],
        nullifier_root: [seed.wrapping_add(2); 48],
        extrinsics_root: [seed.wrapping_add(3); 32],
        message_root: [seed.wrapping_add(4); 48],
        message_count: 0,
        header_mmr_root: [seed.wrapping_add(5); 32],
        header_mmr_len: u64::from(seed).saturating_add(1),
        timestamp_ms: 1_800_000_000_000u64.saturating_add(u64::from(seed)),
        pow_bits: NATIVE_DEV_POW_BITS,
        nonce: [seed.wrapping_add(6); 32],
        work_hash: hash,
        cumulative_work,
        supply_digest: u128::from(seed),
        tx_count: u32::try_from(action_bytes.len()).expect("test tx count"),
        action_bytes,
        da_root: [seed.wrapping_add(7); 48],
        da_chunk_size: MIN_NATIVE_DA_CHUNK_SIZE,
        da_sample_count: DEFAULT_DA_SAMPLE_COUNT,
        da_blob_len: 0,
        da_chunk_count: 0,
    }
}

fn sample_meta_v3(seed: u8, action_bytes: Vec<Vec<u8>>) -> NativeBlockMetaV3 {
    let tx_count = u32::try_from(action_bytes.len()).expect("test V3 tx count");
    let extrinsics_root =
        native_action_root_v3_from_action_bytes(&action_bytes).expect("test V3 action root");
    NativeBlockMetaV3 {
        chain_id: HEGEMON_CHAIN_ID_V1,
        rules_hash: RulesHash48::new([seed.wrapping_add(1); 48]),
        height: u64::from(seed),
        hash: BlockId48::new([seed; 48]),
        parent_hash: BlockId48::new([seed.saturating_sub(1); 48]),
        state_root: StateRoot48::new([seed.wrapping_add(2); 48]),
        kernel_root: KernelRoot48::new([seed.wrapping_add(3); 48]),
        nullifier_root: NullifierAccumulatorRoot48::new([seed.wrapping_add(4); 48]),
        proof_commitment: ProofCommitment48::new([seed.wrapping_add(5); 48]),
        extrinsics_root,
        tx_statements_commitment: TransactionStatementsCommitment48::new(
            [seed.wrapping_add(6); 48],
        ),
        version_commitment: VersionCommitment48::new([seed.wrapping_add(7); 48]),
        fee_commitment: FeeCommitment48::new([seed.wrapping_add(8); 48]),
        message_root: BridgeMessageRoot48::new([seed.wrapping_add(6); 48]),
        message_count: 0,
        header_mmr_root: HeaderMmrHash48::new([seed.wrapping_add(7); 48]),
        header_mmr_len: u64::from(seed).saturating_add(1),
        timestamp_ms: 1_800_000_000_000u64.saturating_add(u64::from(seed)),
        pow_bits: NATIVE_DEV_POW_BITS,
        nonce: [seed.wrapping_add(8); 32],
        work_hash: WorkHash48::new([seed.wrapping_add(9); 48]),
        cumulative_work: Work64::new([seed.wrapping_add(10); 64]),
        supply_digest: u128::from(seed),
        tx_count,
        action_bytes,
        da_root: DaRoot48::new([seed.wrapping_add(11); 48]),
        da_chunk_size: MIN_NATIVE_DA_CHUNK_SIZE,
        da_sample_count: DEFAULT_DA_SAMPLE_COUNT,
        da_blob_len: 0,
        da_chunk_count: 0,
    }
}

fn sample_non_proof_pending_action(seed: u8) -> PendingAction {
    let args = OutboundBridgeArgsV1 {
        destination_chain_id: [seed; 32],
        app_family_id: FAMILY_BRIDGE,
        payload: vec![seed; 32],
    };
    let mut action = PendingAction {
        tx_hash: ActionId48::ZERO,
        binding: protocol_versioning::DEFAULT_VERSION_BINDING.into(),
        family_id: FAMILY_BRIDGE,
        action_id: ACTION_BRIDGE_OUTBOUND,
        anchor: [0u8; 48],
        nullifiers: Vec::new(),
        commitments: Vec::new(),
        ciphertext_hashes: Vec::new(),
        ciphertext_sizes: Vec::new(),
        public_args: args.encode(),
        fee: 0,
        candidate_artifact: None,
    };
    action.tx_hash = pending_action_hash(&action);
    action
}

fn chunks_for(body: &[u8], locator: &NativeBlockBodyLocator) -> Vec<NativeBlockBodyChunk> {
    (0..locator.chunk_count)
        .map(|index| native_block_body_chunk(locator, body, index).expect("test body chunk"))
        .collect()
}

#[test]
fn native_block_body_chunks_roundtrip_out_of_order_and_stay_well_below_frame_cap() {
    let meta = sample_meta(3, vec![vec![0x5a; 2 * 1024 * 1024 + 17]]);
    let (body, locator) = native_block_body_bytes_and_locator(&meta).expect("body locator");
    assert_eq!(locator.chunk_count, 3);
    let chunks = chunks_for(&body, &locator);
    for chunk in &chunks {
        let payload = encode_sync_message(&NativeSyncMessage::BlockBodyChunk {
            chunk: chunk.clone(),
        })
        .expect("encode chunk message");
        assert!(
            native_sync_protocol_frame_bytes(&payload).expect("chunk frame")
                < wire::MAX_WIRE_FRAME_LEN / 2
        );
    }

    let peer = [3u8; 32];
    let now = Instant::now();
    let mut reassembler = NativeBlockBodyReassembler::default();
    assert!(reassembler
        .register(peer, locator.clone(), now)
        .expect("register"));
    assert!(reassembler
        .push_chunk(peer, chunks[2].clone(), now)
        .expect("last first")
        .is_none());
    assert!(reassembler
        .push_chunk(peer, chunks[0].clone(), now)
        .expect("first second")
        .is_none());
    let completed = reassembler
        .push_chunk(peer, chunks[1].clone(), now)
        .expect("middle completes")
        .expect("completed body");
    let decoded = decode_completed_native_block_body(completed).expect("decode completed body");
    assert_eq!(decoded, meta);
    assert_eq!(reassembler.entry_count(), 0);
    assert_eq!(reassembler.reserved_bytes(), 0);
}

#[test]
fn native_v3_body_locator_uses_exact_fixed_width_types_and_one_framed_hash() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let meta = sample_meta_v3(0x31, vec![sample_non_proof_pending_action(0x31).encode()]);
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let (body, locator) =
        native_block_body_v3_bytes_and_locator(&meta).expect("encode typed V3 body locator");
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        locator.body_hash,
        BodyHash48::new(crypto::hashes::blake2b_384_domain_hash(
            crypto::hash384::domains::NATIVE_BLOCK_BODY_V3,
            [body.as_ref()],
        )),
        "the generic frame already commits body length; no second length part is allowed"
    );
    assert_eq!(
        validate_native_block_body_locator_v3(&locator, meta.rules_hash)
            .expect("validate typed V3 locator"),
        body.len()
    );
    assert_eq!(
        bincode::serialize(&locator)
            .expect("serialize V3 locator")
            .len(),
        310,
        "fixed-width V3 locator grammar drifted"
    );
    assert_eq!(
        bincode::serialize(&NativeBlockBodyRequestV3 {
            block_hash: locator.block_hash,
        })
        .expect("serialize V3 request")
        .len(),
        48,
        "BlockId48 must not acquire a length prefix"
    );

    let chunk = native_block_body_chunk_v3(&locator, meta.rules_hash, &body, 0)
        .expect("slice V3 body chunk");
    assert_eq!(
        validate_native_block_body_chunk_v3(&chunk).expect("validate V3 chunk"),
        body.len()
    );
    assert_eq!(
        bincode::serialize(&chunk)
            .expect("serialize V3 chunk")
            .len(),
        124 + body.len(),
        "V3 chunk fixed header must widen by exactly two 16-byte hash deltas"
    );
    let received_body = Arc::clone(&body);
    let (decoded, sealed_body) = decode_and_bind_native_block_body_v3_for_locator(
        &locator,
        meta.rules_hash,
        Arc::clone(&received_body),
    )
    .expect("decode and seal exact canonical V3 body through locator gate");
    assert_eq!(decoded, meta);
    assert_eq!(sealed_body.hash(), locator.body_hash);
    assert_eq!(sealed_body.bytes(), received_body.as_ref());
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        2,
        "V3 completion performs exactly one body hash after locator admission"
    );

    let mut conflicting_body = body.as_ref().to_vec();
    let final_byte = conflicting_body
        .last_mut()
        .expect("encoded V3 body is non-empty");
    *final_byte ^= 1;
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    assert!(decode_and_bind_native_block_body_v3_for_locator(
        &locator,
        meta.rules_hash,
        Arc::from(conflicting_body),
    )
    .expect_err("mutated V3 body must fail its typed hash")
    .to_string()
    .contains("BodyHash48 mismatch"));
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        1
    );

    let mut trailing_body = body.as_ref().to_vec();
    trailing_body.push(0);
    let mut trailing_locator = locator.clone();
    trailing_locator.total_len =
        u64::try_from(trailing_body.len()).expect("trailing V3 body length fits u64");
    trailing_locator.chunk_count =
        native_block_body_chunk_count(trailing_body.len()).expect("trailing V3 chunk count");
    trailing_locator.body_hash = native_block_body_hash_v3(&trailing_body);
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    assert!(decode_and_bind_native_block_body_v3_for_locator(
        &trailing_locator,
        meta.rules_hash,
        Arc::from(trailing_body)
    )
    .expect_err("self-consistent V3 locator must not authorize trailing body bytes")
    .to_string()
    .contains("structural length mismatch"));
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        1,
        "self-consistent trailing bodies must fail only after one authenticated hash"
    );

    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let mut wrong_rules = locator.clone();
    wrong_rules.rules_hash = RulesHash48::new([0xff; 48]);
    assert!(decode_and_bind_native_block_body_v3_for_locator(
        &wrong_rules,
        meta.rules_hash,
        Arc::clone(&received_body),
    )
    .is_err());
    let mut oversized = locator;
    oversized.total_len = u64::try_from(MAX_NATIVE_BLOCK_META_BYTES)
        .expect("metadata cap fits u64")
        .saturating_add(1);
    assert!(decode_and_bind_native_block_body_v3_for_locator(
        &oversized,
        meta.rules_hash,
        received_body,
    )
    .is_err());
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        0,
        "mismatched or oversized V3 locators must reject before hashing"
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        0,
        "mismatched or oversized V3 locators must reject before body allocation"
    );
}

#[test]
fn native_sync_wire_tags_admit_exact_carrier_and_reject_record_fallback_before_allocation() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let (interim_body, interim_locator) =
        native_block_body_bytes_and_locator(&sample_meta(0x32, Vec::new()))
            .expect("interim locator fixture");
    let interim_chunk =
        native_block_body_chunk(&interim_locator, &interim_body, 0).expect("interim chunk fixture");
    for (message, expected_tag) in [
        (
            NativeSyncMessage::AnnounceLocator {
                locator: interim_locator.clone(),
            },
            4,
        ),
        (
            NativeSyncMessage::ResponseLocators {
                best_height: interim_locator.height,
                blocks: vec![interim_locator.clone()],
            },
            5,
        ),
        (
            NativeSyncMessage::BlockBodyRequest {
                block_hash: interim_locator.block_hash,
            },
            6,
        ),
        (
            NativeSyncMessage::BlockBodyChunk {
                chunk: interim_chunk,
            },
            7,
        ),
    ] {
        let encoded = encode_sync_message(&message).expect("encode interim tag fixture");
        assert_eq!(
            encoded[wire::NETWORK_WIRE_MAGIC.len()],
            expected_tag,
            "postcard native sync tag mapping drifted"
        );
    }
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let (_temp, node) = transport_test_node("v3-wire-tag-prefilter-test");
    let reassembler = NativeBlockBodyReassembler::default();
    let sync_before = node.sync_status_fields();

    let tagged = |tag: u8| {
        let mut payload = wire::NETWORK_WIRE_MAGIC.to_vec();
        payload.push(tag);
        payload
    };
    for tag in 0u8..=3 {
        assert_eq!(
            prefilter_native_sync_wire_tag(&tagged(tag)).expect("common native sync wire tag"),
            tag
        );
    }
    for tag in NATIVE_SYNC_EXACT_LOCATOR_BODY_TAGS {
        assert_eq!(
            prefilter_native_sync_wire_tag(&tagged(tag))
                .expect("exact locator/action-body carrier tag"),
            tag
        );
    }
    for tag in NATIVE_SYNC_RECORD_FALLBACK_TAGS {
        let err = prefilter_native_sync_wire_tag(&tagged(tag))
            .expect_err("incompatible stored-record fallback must reject at the tag boundary");
        let rendered = err.to_string();
        assert!(rendered.contains("incompatible"));
        assert!(rendered.contains("before postcard allocation"));
    }
    assert_eq!(
        prefilter_native_sync_wire_tag(&tagged(NATIVE_SYNC_ANNOUNCE_TIP_TAG))
            .expect("bounded compact-tip tag"),
        NATIVE_SYNC_ANNOUNCE_TIP_TAG
    );
    assert!(prefilter_native_sync_wire_tag(wire::NETWORK_WIRE_MAGIC)
        .expect_err("truncated tag")
        .to_string()
        .contains("missing its postcard variant tag"));
    assert!(prefilter_native_sync_wire_tag(b"bad!\x08").is_err());
    assert!(prefilter_native_sync_wire_tag(&tagged(11))
        .expect_err("unknown future tag")
        .to_string()
        .contains("unsupported native sync wire tag"));
    let mut mutated = tagged(*NATIVE_SYNC_EXACT_LOCATOR_BODY_TAGS.start());
    mutated[wire::NETWORK_WIRE_MAGIC.len()] = *NATIVE_SYNC_RECORD_FALLBACK_TAGS.start();
    assert!(prefilter_native_sync_wire_tag(&mutated)
        .expect_err("carrier tag mutated into record fallback")
        .to_string()
        .contains("before postcard allocation"));

    assert_eq!(reassembler.entry_count(), 0);
    assert_eq!(reassembler.reserved_bytes(), 0);
    assert_eq!(node.sync_status_fields(), sync_before);
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn native_block_body_reassembly_rejects_missing_duplicate_conflict_and_cross_block_mix() {
    let meta_a = sample_meta(5, vec![vec![0x11; MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES + 9]]);
    let meta_b = sample_meta(6, vec![vec![0x22; MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES + 9]]);
    let (body_a, locator_a) = native_block_body_bytes_and_locator(&meta_a).expect("body a");
    let (body_b, locator_b) = native_block_body_bytes_and_locator(&meta_b).expect("body b");
    let chunks_a = chunks_for(&body_a, &locator_a);
    let chunks_b = chunks_for(&body_b, &locator_b);
    let peer = [7u8; 32];
    let now = Instant::now();

    let mut missing = NativeBlockBodyReassembler::default();
    missing
        .register(peer, locator_a.clone(), now)
        .expect("register missing");
    assert!(missing
        .push_chunk(peer, chunks_a[0].clone(), now)
        .expect("partial")
        .is_none());
    assert_eq!(missing.entry_count(), 1);

    let duplicate = missing
        .push_chunk(peer, chunks_a[0].clone(), now)
        .expect_err("exact duplicate rejected");
    assert!(duplicate
        .to_string()
        .contains("duplicate native block body chunk"));
    assert_eq!(missing.entry_count(), 1, "exact duplicate keeps progress");

    let mut conflicting = chunks_a[0].clone();
    conflicting.bytes[0] ^= 0xff;
    let conflict = missing
        .push_chunk(peer, conflicting, now)
        .expect_err("conflicting duplicate rejected");
    assert!(conflict.to_string().contains("conflicting duplicate"));
    assert_eq!(missing.entry_count(), 0, "conflict poisons only that body");

    let mut mixed = NativeBlockBodyReassembler::default();
    mixed
        .register(peer, locator_a.clone(), now)
        .expect("register mixed");
    assert!(mixed
        .push_chunk(peer, chunks_b[0].clone(), now)
        .expect_err("cross-block chunk rejected")
        .to_string()
        .contains("unsolicited"));
    assert_eq!(mixed.entry_count(), 1);
    let mut forged_mix = chunks_b[0].clone();
    forged_mix.block_hash = locator_a.block_hash;
    assert!(mixed
        .push_chunk(peer, forged_mix, now)
        .expect_err("same-key conflicting body rejected")
        .to_string()
        .contains("conflicts with requested locator"));
    assert_eq!(mixed.entry_count(), 0);
}

#[test]
fn native_block_body_structural_limits_reject_before_reservation_or_large_decode() {
    let meta = sample_meta(8, Vec::new());
    let (body, locator) = native_block_body_bytes_and_locator(&meta).expect("body");
    let peer = [8u8; 32];
    let now = Instant::now();

    let mut interim_schema = locator.clone();
    interim_schema.schema_version = 2;
    let mut reassembler = NativeBlockBodyReassembler::default();
    assert!(reassembler.register(peer, interim_schema, now).is_err());
    assert_eq!(reassembler.entry_count(), 0);
    assert_eq!(reassembler.reserved_bytes(), 0);

    let mut unknown_schema = locator.clone();
    unknown_schema.schema_version = NATIVE_BLOCK_BODY_SCHEMA_VERSION.saturating_add(1);
    assert!(reassembler.register(peer, unknown_schema, now).is_err());
    assert_eq!(reassembler.entry_count(), 0);
    assert_eq!(reassembler.reserved_bytes(), 0);
    let mut wrong_chain = locator.clone();
    wrong_chain.chain_id[0] ^= 1;
    let mut reassembler = NativeBlockBodyReassembler::default();
    assert!(reassembler.register(peer, wrong_chain, now).is_err());
    assert_eq!(reassembler.reserved_bytes(), 0);

    let mut wrong_rules = locator.clone();
    wrong_rules.rules_hash[0] ^= 1;
    assert!(reassembler.register(peer, wrong_rules, now).is_err());
    assert_eq!(reassembler.reserved_bytes(), 0);

    let mut oversized = locator.clone();
    oversized.total_len = (MAX_NATIVE_BLOCK_META_BYTES as u64).saturating_add(1);
    oversized.chunk_count = u32::try_from(MAX_NATIVE_BLOCK_BODY_CHUNKS + 1).expect("count");
    assert!(reassembler.register(peer, oversized, now).is_err());
    assert_eq!(reassembler.reserved_bytes(), 0);

    let mut oversized_wire_chunk = native_block_body_chunk(&locator, &body, 0).expect("chunk");
    oversized_wire_chunk.bytes = vec![0u8; MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES + 1];
    oversized_wire_chunk.chunk_len =
        u32::try_from(oversized_wire_chunk.bytes.len()).expect("oversized chunk len");
    let encoded = encode_sync_message(&NativeSyncMessage::BlockBodyChunk {
        chunk: oversized_wire_chunk,
    })
    .expect("encode adversarial oversized chunk");
    assert!(
        decode_sync_message(&encoded).is_err(),
        "bounded chunk deserializer rejects before reassembly"
    );
}

#[test]
fn native_block_body_reassembly_enforces_peer_global_byte_idle_and_absolute_caps() {
    let now = Instant::now();
    let mut reassembler = NativeBlockBodyReassembler::default();
    let (_, first) =
        native_block_body_bytes_and_locator(&sample_meta(10, Vec::new())).expect("first locator");
    reassembler
        .register([1u8; 32], first.clone(), now)
        .expect("first register");
    let (_, same_peer) = native_block_body_bytes_and_locator(&sample_meta(11, Vec::new()))
        .expect("same peer locator");
    assert!(reassembler
        .register([1u8; 32], same_peer, now)
        .expect_err("per-peer cap")
        .to_string()
        .contains("per-peer"));

    for seed in 2..=MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL {
        let (_, locator) = native_block_body_bytes_and_locator(&sample_meta(
            u8::try_from(seed + 10).expect("seed"),
            Vec::new(),
        ))
        .expect("global locator");
        reassembler
            .register([u8::try_from(seed).expect("peer"); 32], locator, now)
            .expect("global slot");
    }
    let (_, overflow) = native_block_body_bytes_and_locator(&sample_meta(30, Vec::new()))
        .expect("overflow locator");
    assert!(reassembler
        .register([30u8; 32], overflow, now)
        .expect_err("global cap")
        .to_string()
        .contains("global reassembly"));
    assert!(reassembler.reserved_bytes() <= MAX_NATIVE_BLOCK_BODY_REASSEMBLY_RESERVED_BYTES);

    assert_eq!(
        reassembler.prune_expired(now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL),
        MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL
    );
    assert_eq!(reassembler.reserved_bytes(), 0);

    let mut absolute = NativeBlockBodyReassembler::default();
    absolute
        .register([9u8; 32], first.clone(), now)
        .expect("absolute register");
    let absolute_deadline = now + NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME;
    absolute.set_reassembly_times_for_test(
        [9u8; 32],
        first.block_hash,
        now,
        absolute_deadline - Duration::from_secs(1),
    );
    assert_eq!(absolute.prune_expired(absolute_deadline), 1);
}

#[test]
fn native_block_body_transport_rotates_withholders_and_aborts_range_suffix() {
    let now = Instant::now();
    let mut transport = NativeBlockBodyTransport::default();
    for seed in 1u8..=5 {
        let (_, locator) =
            native_block_body_bytes_and_locator(&sample_meta(seed, Vec::new())).expect("locator");
        transport
            .enqueue_announce([seed; 32], locator)
            .expect("queue announce");
        let started = transport.start_next([seed; 32], now);
        if usize::from(seed) <= MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL {
            assert!(started.expect("start result").is_some());
        } else {
            assert!(started.is_err(), "fifth peer waits under global cap");
        }
    }
    let retry = transport.expire_and_retry(now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL);
    assert!(
        retry.requests.iter().any(|(peer, _)| *peer == [5u8; 32]),
        "round-robin rotation admits the previously waiting honest peer"
    );

    let mut range_transport = NativeBlockBodyTransport::default();
    let mut locators: Vec<NativeBlockBodyLocator> = Vec::new();
    for seed in 40u8..43 {
        let (_, mut locator) = native_block_body_bytes_and_locator(&sample_meta(seed, Vec::new()))
            .expect("range locator");
        if let Some(previous) = locators.last() {
            locator.height = previous.height + 1;
            locator.parent_hash = previous.block_hash;
        }
        locators.push(locator);
    }
    let range_peer = [44u8; 32];
    let response_range = NativeSyncRange {
        from_height: locators.first().expect("first range locator").height,
        to_height: locators.last().expect("last range locator").height,
    };
    let completed_request = NativeCompletedSyncRequest {
        request_target: Some(range_peer),
        range: response_range,
        context: NativeOutboundSyncRequestContext::default(),
    };
    range_transport
        .enqueue_range(range_peer, 100, locators, completed_request)
        .expect("enqueue range")
        .expect("range");
    range_transport
        .start_next(range_peer, now)
        .expect("start range")
        .expect("range request");
    let first_retry = range_transport.expire_and_retry(now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL);
    assert!(first_retry.aborted.is_empty());
    let terminal = range_transport.expire_and_retry(
        now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL + NATIVE_BLOCK_BODY_REASSEMBLY_TTL,
    );
    assert_eq!(terminal.aborted.len(), 1);
    assert_eq!(terminal.aborted[0].1.len(), 3, "suffix canceled with head");
    assert_eq!(range_transport.queued_bodies_for_test(), 0);

    let mut absolute_transport = NativeBlockBodyTransport::default();
    let (_, absolute_locator) = native_block_body_bytes_and_locator(&sample_meta(45, Vec::new()))
        .expect("absolute locator");
    let absolute_peer = [45u8; 32];
    absolute_transport
        .enqueue_announce(absolute_peer, absolute_locator)
        .expect("enqueue absolute locator");
    absolute_transport
        .start_next(absolute_peer, now)
        .expect("start absolute locator")
        .expect("absolute request");
    let retry = absolute_transport.expire_and_retry(now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL);
    assert_eq!(retry.requests.len(), 1, "idle expiry receives one retry");
    let absolute_terminal =
        absolute_transport.expire_and_retry(now + NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME);
    assert_eq!(
        absolute_terminal.aborted.len(),
        1,
        "retry preserves the original absolute request epoch"
    );
    assert_eq!(absolute_transport.queued_bodies_for_test(), 0);
}

#[test]
fn native_block_body_64_mib_action_boundary_serializes_hashes_and_reassembles_linearly() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let action_bytes = (0..32)
        .map(|index| vec![u8::try_from(index).expect("byte"); 2 * 1024 * 1024])
        .collect::<Vec<_>>();
    assert_eq!(
        action_bytes.iter().map(Vec::len).sum::<usize>(),
        MAX_NATIVE_BLOCK_ACTION_BYTES
    );
    let meta = sample_meta(70, action_bytes);
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let (body, locator) = native_block_body_bytes_and_locator(&meta).expect("64 MiB body");
    assert!(body.len() > MAX_NATIVE_BLOCK_ACTION_BYTES);
    assert!(body.len() <= MAX_NATIVE_BLOCK_META_BYTES);
    assert!(usize::try_from(locator.chunk_count).expect("count") <= MAX_NATIVE_BLOCK_BODY_CHUNKS);
    drop(meta);

    let peer = [70u8; 32];
    let now = Instant::now();
    let mut reassembler = NativeBlockBodyReassembler::default();
    reassembler
        .register(peer, locator.clone(), now)
        .expect("register 64 MiB body");
    let mut completed = None;
    for index in 0..locator.chunk_count {
        let chunk = native_block_body_chunk(&locator, &body, index).expect("linear chunk");
        completed = reassembler
            .push_chunk(peer, chunk, now)
            .expect("linear chunk admission")
            .or(completed);
    }
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        1,
        "offered body is serialized once"
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        1,
        "offered body is hashed once before chunk slicing"
    );
    drop(body);
    let decoded = decode_completed_native_block_body(completed.expect("complete 64 MiB body"))
        .expect("decode 64 MiB body");
    assert_eq!(
        decoded.action_bytes.iter().map(Vec::len).sum::<usize>(),
        MAX_NATIVE_BLOCK_ACTION_BYTES
    );
}

#[test]
fn large_announce_and_multiblock_sync_use_small_locator_messages() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let large = sample_meta(
        80,
        vec![vec![0x80; MAX_NATIVE_INLINE_BLOCK_ANNOUNCE_BYTES + 1]],
    );
    let announce = native_block_announce_message(&large).expect("large announce message");
    assert!(matches!(
        announce,
        NativeSyncMessage::AnnounceLocator { .. }
    ));
    let announce_payload = encode_sync_message(&announce).expect("announce payload");
    assert!(
        native_sync_protocol_frame_bytes(&announce_payload).expect("announce frame")
            < MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES
    );

    let mut next = sample_meta(81, Vec::new());
    next.parent_hash = large.hash;
    next.height = large.height + 1;
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let response =
        native_sync_response_message(100, vec![large, next]).expect("multi-block locator response");
    let NativeSyncMessage::ResponseLocators { blocks, .. } = &response else {
        panic!("large response must use locators");
    };
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[1].parent_hash, blocks[0].block_hash);
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        2
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        2
    );
    let response_payload = encode_sync_message(&response).expect("response payload");
    assert!(
        native_sync_protocol_frame_bytes(&response_payload).expect("response frame")
            < MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES
    );
}

#[test]
fn withheld_unverified_locator_never_changes_native_mining_sync_gate() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config = NativeConfig {
        dev: true,
        tmp: false,
        base_path: temp.path().to_path_buf(),
        db_path: temp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "transport-gate-test".to_string(),
        rpc_methods: "safe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: vec!["127.0.0.1:30333".to_string()],
        max_peers: 1,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: true,
        miner_address: None,
        pow_bits: NATIVE_DEV_POW_BITS,
    };
    let node = NativeNode::open(config).expect("test node");
    assert!(node.mining_sync_gate_allows_work());
    let (_, mut locator) = native_block_body_bytes_and_locator(&sample_meta(90, Vec::new()))
        .expect("withheld locator");
    locator.height = u64::MAX;
    locator.block_hash = [0xee; 32];
    let peer = [0xef; 32];
    let now = Instant::now();
    let mut transport = NativeBlockBodyTransport::default();
    transport
        .enqueue_announce(peer, locator)
        .expect("queue unverified locator");
    transport
        .start_next(peer, now)
        .expect("start locator")
        .expect("request locator body");
    assert!(node.mining_sync_gate_allows_work());
    let first = transport.expire_and_retry(now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL);
    assert!(first.aborted.is_empty());
    let terminal = transport.expire_and_retry(
        now + NATIVE_BLOCK_BODY_REASSEMBLY_TTL + NATIVE_BLOCK_BODY_REASSEMBLY_TTL,
    );
    assert_eq!(terminal.aborted.len(), 1);
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(node.sync_status_fields().1, 0);
}

#[test]
fn known_taller_nonwinning_locator_never_closes_native_mining_sync_gate() {
    let temp = tempfile::tempdir().expect("temp dir");
    let config = NativeConfig {
        dev: true,
        tmp: false,
        base_path: temp.path().to_path_buf(),
        db_path: temp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: "known-locator-gate-test".to_string(),
        rpc_methods: "safe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: vec!["127.0.0.1:30333".to_string()],
        max_peers: 1,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: true,
        miner_address: None,
        pow_bits: 0x207f_ffff,
    };
    let node = NativeNode::open(config).expect("test node");
    let work = node.prepare_work().expect("prepare local winning work");
    let seal = mine_native_round(work.clone(), 0).expect("mine local winning work");
    node.import_mined_block(&work, seal)
        .expect("import local winning work")
        .expect("local winning block");
    let local_best = node.best_meta();
    let mut known = sample_meta(91, Vec::new());
    known.height = local_best.height + 1;
    known.parent_hash = local_best.hash;
    known.cumulative_work = [0; 48];
    known.action_bytes = vec![vec![0x91; 2 * 1024 * 1024]; 32];
    known.tx_count = 32;
    assert!(!native_meta_better_than(&known, &local_best));
    node.persist_noncanonical_block_record(&known)
        .expect("persist known non-winning record");
    assert!(node
        .header_by_hash(&known.hash)
        .expect("read known record")
        .is_some());

    node.reset_full_block_body_load_invocations();
    assert!(node
        .has_verified_header_hash(&local_best.hash)
        .expect("check compact canonical header"));
    assert!(node
        .has_verified_header_hash(&known.hash)
        .expect("check compact noncanonical header"));
    assert!(!admit_known_native_block_locator(&node, [0x91; 32], &known,));
    assert_eq!(
        node.full_block_body_load_invocations(),
        0,
        "known canonical/non-winning locator admission must not load or decode a maximum body"
    );

    assert!(node.mining_sync_gate_allows_work());
    assert!(node.sync_status_fields().1 <= local_best.height);
    assert_eq!(*node.sync_target_peer.lock(), None);
    assert_eq!(*node.sync_target_hash.lock(), None);
}

#[test]
fn bounded_fair_sync_import_queue_preserves_waiting_peer_and_fails_closed() {
    let mut queue = NativeSyncImportQueue::default();
    let peer_a = [0xa1; 32];
    let peer_b = [0xb2; 32];
    queue
        .enqueue(NativeSyncImportWork::Announce {
            peer_id: peer_a,
            meta: sample_meta(0xa1, Vec::new()),
        })
        .expect("queue peer A");
    let active = queue.pop_front().expect("activate peer A");
    assert_eq!(active.peer_id(), peer_a);
    assert_eq!(queue.active_peer(), Some(peer_a));

    queue
        .enqueue(NativeSyncImportWork::Announce {
            peer_id: peer_b,
            meta: sample_meta(0xb2, Vec::new()),
        })
        .expect("queue peer B while A imports");
    assert_eq!(queue.waiting_len(), 1);
    assert!(queue
        .enqueue(NativeSyncImportWork::Announce {
            peer_id: peer_b,
            meta: sample_meta(0xb3, Vec::new()),
        })
        .expect_err("one candidate per peer")
        .to_string()
        .contains("already has an import"));
    queue.finish(peer_a);
    let next = queue.pop_front().expect("peer B remains queued");
    assert_eq!(next.peer_id(), peer_b);
    assert_eq!(queue.active_peer(), Some(peer_b));
    queue.finish(peer_b);
    assert_eq!(queue.waiting_len(), 0);
    assert_eq!(queue.reserved_bytes(), 0);

    let mut item_bounded = NativeSyncImportQueue::default();
    for index in 0..MAX_NATIVE_SYNC_IMPORT_QUEUE_ITEMS {
        item_bounded
            .enqueue(NativeSyncImportWork::Announce {
                peer_id: [u8::try_from(index).expect("peer index"); 32],
                meta: sample_meta(u8::try_from(index + 1).expect("meta index"), Vec::new()),
            })
            .expect("fill bounded import queue");
    }
    assert!(item_bounded
        .enqueue(NativeSyncImportWork::Announce {
            peer_id: [0xfe; 32],
            meta: sample_meta(0xfe, Vec::new()),
        })
        .expect_err("global item cap")
        .to_string()
        .contains("item limit"));

    let (_, locator) =
        native_block_body_bytes_and_locator(&sample_meta(0x71, Vec::new())).expect("test locator");
    let mut byte_bounded = NativeSyncImportQueue::default();
    for peer_seed in [0x71, 0x72] {
        byte_bounded
            .enqueue(NativeSyncImportWork::CompletedAnnounce {
                peer_id: [peer_seed; 32],
                completed: NativeCompletedBlockBody::for_import_queue_budget_test(
                    locator.clone(),
                    MAX_NATIVE_BLOCK_META_BYTES,
                ),
            })
            .expect("fill bounded import byte budget");
    }
    assert_eq!(
        byte_bounded.reserved_bytes(),
        MAX_NATIVE_SYNC_IMPORT_QUEUE_BYTES
    );
    assert!(byte_bounded
        .enqueue(NativeSyncImportWork::CompletedAnnounce {
            peer_id: [0x73; 32],
            completed: NativeCompletedBlockBody::for_import_queue_budget_test(locator, 1),
        })
        .expect_err("global byte cap")
        .to_string()
        .contains("byte limit"));
}

fn transport_test_node(name: &str) -> (tempfile::TempDir, Arc<NativeNode>) {
    let temp = tempfile::tempdir().expect("temp dir");
    let config = NativeConfig {
        dev: true,
        tmp: false,
        base_path: temp.path().to_path_buf(),
        db_path: temp.path().join("native-chain.sled"),
        rpc_addr: "127.0.0.1:0".parse().expect("rpc addr"),
        p2p_listen_addr: "127.0.0.1:0".to_string(),
        node_name: name.to_string(),
        rpc_methods: "safe".to_string(),
        rpc_external: false,
        rpc_cors: None,
        seeds: vec!["127.0.0.1:30333".to_string()],
        max_peers: 1,
        mine: false,
        mine_threads: 1,
        bootstrap_mining_authoring: true,
        miner_address: None,
        pow_bits: NATIVE_DEV_POW_BITS,
    };
    let node = NativeNode::open(config).expect("test node");
    (temp, node)
}

#[test]
fn block_body_abort_defers_only_the_exact_owned_range() {
    let (_temp, node) = transport_test_node("body-range-owner-test");
    let peer = [0x93; 32];
    let peer_range = NativeSyncRange {
        from_height: 1,
        to_height: 64,
    };
    let generic_range = NativeSyncRange {
        from_height: 65,
        to_height: 128,
    };
    assert!(node.begin_outbound_sync_request(Some(peer), peer_range));
    assert!(node.begin_outbound_sync_request(None, generic_range));
    let peer_completed_request = node
        .complete_outbound_sync_response(peer, Some(peer_range))
        .expect("complete exact peer-owned body range request");

    complete_native_block_body_range_origins(
        &node,
        peer,
        &[NativeQueuedBlockBodyOrigin::Range {
            best_height: 128,
            response_range: peer_range,
            final_pending_body: false,
            response_tip_hash: None,
            completed_request: peer_completed_request,
        }],
    );
    assert!(
        !node.begin_outbound_sync_request(Some(peer), peer_range),
        "aborted peer range must enter bounded retry cooldown"
    );
    assert!(
        !node.begin_outbound_sync_request(None, generic_range),
        "peer-range abort must preserve the unrelated generic request"
    );
    node.complete_outbound_sync_request_target(Some(peer));
    assert!(
        !node.begin_outbound_sync_request(None, generic_range),
        "exact peer cleanup must not cancel the generic request"
    );
    node.complete_outbound_sync_request_target(None);

    assert!(node.begin_outbound_sync_request(None, peer_range));
    assert!(node.begin_outbound_sync_request(Some(peer), generic_range));
    let generic_completed_request = node
        .complete_outbound_sync_response(peer, Some(peer_range))
        .expect("complete exact broadcast body range request");
    complete_native_block_body_range_origins(
        &node,
        peer,
        &[NativeQueuedBlockBodyOrigin::Range {
            best_height: 128,
            response_range: peer_range,
            final_pending_body: true,
            response_tip_hash: None,
            completed_request: generic_completed_request,
        }],
    );
    assert!(
        !node.begin_outbound_sync_request(None, peer_range),
        "aborted generic range must enter bounded retry cooldown"
    );
    assert!(
        !node.begin_outbound_sync_request(Some(peer), generic_range),
        "generic-range abort must preserve the unrelated peer request"
    );
}

#[test]
fn non_proof_relay_queue_enforces_per_peer_global_item_and_byte_caps() {
    let peer = [0xa4; 32];
    let mut per_peer = NativePeerNonProofQueue::default();
    per_peer
        .admit(peer, sample_non_proof_pending_action(1))
        .expect("first peer relay");
    per_peer
        .admit(peer, sample_non_proof_pending_action(2))
        .expect("second peer relay");
    assert_eq!(
        per_peer
            .admit(peer, sample_non_proof_pending_action(3))
            .expect_err("per-peer outstanding cap"),
        NativePeerNonProofAdmissionRejection::PerPeerOutstanding
    );

    let mut item_bounded = NativePeerNonProofQueue::default();
    for index in 0..MAX_NATIVE_PEER_NON_PROOF_QUEUE {
        let mut peer_id = [0u8; 32];
        peer_id[..8].copy_from_slice(
            &u64::try_from(index)
                .expect("queue index fits u64")
                .to_le_bytes(),
        );
        item_bounded
            .admit(peer_id, sample_non_proof_pending_action(index as u8))
            .expect("fill bounded non-proof relay queue");
    }
    assert_eq!(
        item_bounded
            .admit([0xff; 32], sample_non_proof_pending_action(0xff))
            .expect_err("global non-proof item cap"),
        NativePeerNonProofAdmissionRejection::QueueFull
    );
    assert_eq!(
        item_bounded.reserved_items(),
        MAX_NATIVE_PEER_NON_PROOF_QUEUE
    );

    let mut byte_bounded = NativePeerNonProofQueue::default();
    byte_bounded
        .admit_charged_for_test(
            [0xb1; 32],
            sample_non_proof_pending_action(0xb1),
            MAX_NATIVE_PEER_NON_PROOF_QUEUE_BYTES,
        )
        .expect("exact global non-proof byte cap");
    assert_eq!(
        byte_bounded
            .admit_charged_for_test([0xb2; 32], sample_non_proof_pending_action(0xb2), 1,)
            .expect_err("global non-proof byte cap"),
        NativePeerNonProofAdmissionRejection::QueueBytes
    );
    assert_eq!(
        byte_bounded.reserved_bytes(),
        MAX_NATIVE_PEER_NON_PROOF_QUEUE_BYTES
    );
}

#[test]
fn peer_action_route_prefix_rejects_unauthorized_proof_floods_before_full_scale_decode() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let mut inline = sample_non_proof_pending_action(0xce);
    inline.family_id = FAMILY_SHIELDED_POOL;
    inline.action_id = ACTION_SHIELDED_TRANSFER_INLINE;
    inline.tx_hash = pending_action_hash(&inline);
    let inline_wire = inline.encode();
    assert_eq!(
        &inline_wire[..48],
        inline.tx_hash.as_bytes(),
        "active V3 SCALE prefix must begin with the fixed ActionId48"
    );
    assert_eq!(&inline_wire[48..50], &inline.binding.circuit.to_le_bytes());
    assert_eq!(
        &inline_wire[50..NATIVE_PENDING_ACTION_V3_FAMILY_ID_OFFSET],
        &inline.binding.crypto.to_le_bytes()
    );
    assert_eq!(
        &inline_wire
            [NATIVE_PENDING_ACTION_V3_FAMILY_ID_OFFSET..NATIVE_PENDING_ACTION_V3_ACTION_ID_OFFSET],
        &inline.family_id.to_le_bytes()
    );
    assert_eq!(
        &inline_wire[NATIVE_PENDING_ACTION_V3_ACTION_ID_OFFSET
            ..NATIVE_PENDING_ACTION_V3_FIXED_PREFIX_BYTES],
        &inline.action_id.to_le_bytes()
    );

    NATIVE_PENDING_ACTION_PEER_FULL_DECODE_INVOCATIONS.store(0, Ordering::Relaxed);
    for truncated_len in 0..NATIVE_PENDING_ACTION_V3_FIXED_PREFIX_BYTES {
        assert!(decode_native_peer_pending_action_v3(&inline_wire[..truncated_len], 1).is_err());
    }

    let mut inactive = sample_non_proof_pending_action(0xcf);
    inactive.public_args = vec![0x5a; 1024 * 1024];
    inactive.tx_hash = pending_action_hash(&inactive);
    let inactive_wire = inactive.encode();
    for _ in 0..64 {
        assert!(decode_native_peer_pending_action_v3(&inactive_wire, 1).is_err());
    }
    let mut unknown = inline.clone();
    unknown.family_id = u16::MAX;
    unknown.action_id = u16::MAX;
    unknown.tx_hash = pending_action_hash(&unknown);
    assert!(decode_native_peer_pending_action_v3(&unknown.encode(), 1).is_err());
    assert_eq!(
        NATIVE_PENDING_ACTION_PEER_FULL_DECODE_INVOCATIONS.load(Ordering::Relaxed),
        0,
        "truncated, inactive, and unknown peer actions must reject before any length-bearing SCALE decode"
    );

    let err = decode_native_peer_pending_action_v3(&inline_wire, 1)
        .expect_err("decoder-compatible V4 inline action has no fresh authority");
    assert!(err.to_string().contains("fresh proof authority"), "{err}");
    assert_eq!(
        NATIVE_PENDING_ACTION_PEER_FULL_DECODE_INVOCATIONS.load(Ordering::Relaxed),
        0,
        "fresh proof authority must reject before length-bearing SCALE decode"
    );

    let legacy_v2 = LegacyPendingActionV2 {
        tx_hash: inline.tx_hash,
        binding: inline.binding,
        family_id: inline.family_id,
        action_id: inline.action_id,
        anchor: inline.anchor,
        nullifiers: inline.nullifiers.clone(),
        commitments: inline.commitments.clone(),
        ciphertext_hashes: inline.ciphertext_hashes.clone(),
        ciphertext_sizes: inline.ciphertext_sizes.clone(),
        public_args: inline.public_args.clone(),
        fee: inline.fee,
        candidate_artifact: inline.candidate_artifact.clone(),
        received_ms: u64::MAX,
    };
    let err = decode_native_peer_pending_action_v3(&legacy_v2.encode(), 1)
        .expect_err("legacy grammar must not bypass absent fresh proof authority");
    assert!(err.to_string().contains("fresh proof authority"), "{err}");
    assert_eq!(
        NATIVE_PENDING_ACTION_PEER_FULL_DECODE_INVOCATIONS.load(Ordering::Relaxed),
        0
    );

    let legacy_v1 = LegacyPendingActionV1 {
        tx_hash: [0x11; 32],
        binding: inline.binding,
        family_id: inline.family_id,
        action_id: inline.action_id,
        anchor: [0; 48],
        nullifiers: inline.nullifiers,
        commitments: inline.commitments,
        ciphertext_hashes: inline.ciphertext_hashes,
        ciphertext_sizes: inline.ciphertext_sizes,
        public_args: inline.public_args,
        fee: inline.fee,
        candidate_artifact: inline.candidate_artifact,
        received_ms: 0,
    };
    let err = decode_native_peer_pending_action_v3(&legacy_v1.encode(), 1)
        .expect_err("legacy V1 offset alias must fail closed at the V3 prefix");
    assert!(err
        .to_string()
        .contains("unsupported native V3 action route"));
    assert_eq!(
        NATIVE_PENDING_ACTION_PEER_FULL_DECODE_INVOCATIONS.load(Ordering::Relaxed),
        0,
        "legacy V1 must not reach active full decode under the fixed V3 offsets"
    );
}

#[test]
fn peer_action_preflight_rejects_inactive_routes_and_forged_ids_before_queue_reservation() {
    let (_temp, node) = transport_test_node("peer-action-preflight-queue-test");
    let proof_queue = NativePeerPendingProofQueue::default();
    let non_proof_queue = NativePeerNonProofQueue::default();

    let bridge = sample_non_proof_pending_action(0xd0);
    let mut sidecar = sample_non_proof_pending_action(0xd1);
    sidecar.family_id = FAMILY_SHIELDED_POOL;
    sidecar.action_id = ACTION_SHIELDED_TRANSFER_SIDECAR;
    sidecar.tx_hash = pending_action_hash(&sidecar);
    let mut candidate = sample_non_proof_pending_action(0xd2);
    candidate.family_id = FAMILY_SHIELDED_POOL;
    candidate.action_id = ACTION_SUBMIT_CANDIDATE_ARTIFACT;
    candidate.tx_hash = pending_action_hash(&candidate);
    let mut external_coinbase = sample_non_proof_pending_action(0xd3);
    external_coinbase.family_id = FAMILY_SHIELDED_POOL;
    external_coinbase.action_id = ACTION_MINT_COINBASE;
    external_coinbase.tx_hash = pending_action_hash(&external_coinbase);
    let mut unknown = sample_non_proof_pending_action(0xd5);
    unknown.family_id = u16::MAX;
    unknown.action_id = u16::MAX;
    unknown.tx_hash = pending_action_hash(&unknown);

    for (label, pending) in [
        ("bridge", bridge),
        ("sidecar", sidecar),
        ("candidate", candidate),
        ("external_coinbase", external_coinbase),
        ("unknown", unknown),
    ] {
        validate_pending_action_identity(&pending)
            .unwrap_or_else(|err| panic!("{label} fixture has canonical identity: {err}"));
        let err = preflight_native_peer_pending_action(&pending, 0)
            .expect_err("inactive V3 route must fail before queue admission");
        assert!(
            err.to_string().contains("inactive")
                || err.to_string().contains("internal mining outputs")
                || err.to_string().contains("pending a PQ128")
                || err
                    .to_string()
                    .contains("unsupported native V3 action route"),
            "unexpected {label} preflight rejection: {err}"
        );
        assert_eq!(proof_queue.reserved_items(), 0, "{label} proof items");
        assert_eq!(proof_queue.reserved_bytes(), 0, "{label} proof bytes");
        assert_eq!(
            non_proof_queue.reserved_items(),
            0,
            "{label} non-proof items"
        );
        assert_eq!(
            non_proof_queue.reserved_bytes(),
            0,
            "{label} non-proof bytes"
        );
        assert!(
            node.pending_proof_admissions_in_flight.lock().is_empty(),
            "{label} must not acquire a proof single-flight slot"
        );
    }

    let mut forged_inline = sample_non_proof_pending_action(0xd4);
    forged_inline.family_id = FAMILY_SHIELDED_POOL;
    forged_inline.action_id = ACTION_SHIELDED_TRANSFER_INLINE;
    forged_inline.tx_hash = pending_action_hash(&forged_inline);
    let err = preflight_native_peer_pending_action(&forged_inline, 0)
        .expect_err("decoder-compatible inline transfer has no fresh proof authority");
    assert!(err.to_string().contains("fresh proof authority"), "{err}");
    forged_inline.tx_hash = ActionId48::new([0xa5; 48]);
    let err = preflight_native_peer_pending_action(&forged_inline, 0)
        .expect_err("forged inline route must fail before proof admission");
    assert!(err.to_string().contains("fresh proof authority"), "{err}");
    assert_eq!(proof_queue.reserved_items(), 0);
    assert_eq!(proof_queue.reserved_bytes(), 0);
    assert_eq!(non_proof_queue.reserved_items(), 0);
    assert_eq!(non_proof_queue.reserved_bytes(), 0);
    assert_eq!(non_proof_queue.active(), 0);
    assert!(node.pending_proof_admissions_in_flight.lock().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn inactive_peer_relays_spawn_no_group_or_proof_worker() {
    let (_temp, node) = transport_test_node("inactive-non-proof-relay-runtime-test");
    node.pending_action_group_commit_test
        .hold_before_flush
        .store(true, Ordering::Release);
    let proof_queue = NativePeerPendingProofQueue::default();
    let non_proof_queue = NativePeerNonProofQueue::default();

    let bridge = sample_non_proof_pending_action(0xc1);
    let mut unknown = sample_non_proof_pending_action(0xc2);
    unknown.family_id = u16::MAX;
    unknown.action_id = u16::MAX;
    unknown.tx_hash = pending_action_hash(&unknown);
    for pending in [&bridge, &unknown] {
        preflight_native_peer_pending_action(pending, 0)
            .expect_err("inactive and unknown non-proof relays must fail before worker admission");
    }

    tokio::time::timeout(
        Duration::from_millis(250),
        tokio::time::sleep(Duration::from_millis(10)),
    )
    .await
    .expect("Tokio heartbeat must progress without spawning a group-commit worker");
    assert!(
        !node
            .pending_action_group_commit_test
            .before_flush_entered
            .load(Ordering::Acquire),
        "rejected peer routes must never reach the held group durability barrier"
    );
    assert_eq!(proof_queue.reserved_items(), 0);
    assert_eq!(proof_queue.reserved_bytes(), 0);
    assert_eq!(non_proof_queue.reserved_items(), 0);
    assert_eq!(non_proof_queue.reserved_bytes(), 0);
    assert!(node.pending_proof_admissions_in_flight.lock().is_empty());

    let mut best_announce_cache = NativeBestAnnounceCache::default();
    tokio::time::timeout(
        Duration::from_secs(2),
        native_best_announce_payload(&node, &mut best_announce_cache),
    )
    .await
    .expect("block announce encoding must progress after rejected peer relays")
    .expect("encode best block announce");

    let mut inline = sample_non_proof_pending_action(0xc3);
    inline.family_id = FAMILY_SHIELDED_POOL;
    inline.action_id = ACTION_SHIELDED_TRANSFER_INLINE;
    inline.tx_hash = pending_action_hash(&inline);
    let err = preflight_native_peer_pending_action(&inline, 0)
        .expect_err("decoder-compatible inline transfer has no fresh proof authority");
    assert!(err.to_string().contains("fresh proof authority"), "{err}");
    assert_eq!(proof_queue.reserved_items(), 0);
    assert_eq!(proof_queue.reserved_bytes(), 0);
    assert_eq!(non_proof_queue.reserved_items(), 0);
    assert!(node.pending_proof_admissions_in_flight.lock().is_empty());
    assert!(
        !node
            .pending_action_group_commit_test
            .before_flush_entered
            .load(Ordering::Acquire),
        "inactive inline transfer must not reach the held durability barrier"
    );

    node.pending_action_group_commit_test
        .hold_before_flush
        .store(false, Ordering::Release);
    node.pending_action_group_commit_test.wake.notify_all();
    node.pending_action_group_commit.wake.notify_all();
}

#[test]
fn known_locator_same_hash_different_body_is_rejected_before_sync_credit_or_cache_trust() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let (_temp, node) = transport_test_node("known-body-locator-binding-test");
    let local_best = node.best_meta();
    let mut known = sample_meta(0x92, vec![vec![0x11; 1024]]);
    known.height = local_best.height.saturating_add(1);
    known.parent_hash = local_best.hash;
    known.cumulative_work = [0xff; 48];

    let mut conflicting_body = known.clone();
    conflicting_body.action_bytes = vec![vec![0x22; 1024]];
    let cached_conflicting_locator = node
        .block_body_send_cache
        .lock()
        .encode_meta(&conflicting_body)
        .expect("cache conflicting same-hash body for adversarial test")
        .locator
        .clone();
    assert_eq!(cached_conflicting_locator.block_hash, known.hash);
    assert!(admit_known_native_block_locator(&node, [0x92; 32], &known));
    assert!(node.mining_sync_gate_allows_work());

    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let error = validate_known_native_block_body_locator(&known, &cached_conflicting_locator)
        .expect_err("same block hash with different canonical body must be rejected");
    assert!(error
        .to_string()
        .contains("conflicts with exact stored canonical body"));
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        1,
        "known-body validation must rebuild the exact stored body instead of trusting the cache"
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        1
    );
    assert!(node.mining_sync_gate_allows_work());
    assert_eq!(node.sync_status_fields().1, local_best.height);
    assert_eq!(*node.sync_target_peer.lock(), None);
    assert_eq!(*node.sync_target_hash.lock(), None);
}

#[test]
fn outbound_body_cache_encodes_once_and_over_budget_rejection_encodes_zero_times() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let (_temp, node) = transport_test_node("body-send-cache-test");
    let best = node.best_meta();
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    node.block_body_send_cache
        .lock()
        .load_or_encode(&node, best.hash)
        .expect("first outbound body encoding");
    node.block_body_send_cache
        .lock()
        .load_or_encode(&node, best.hash)
        .expect("cached outbound body encoding");
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        1
    );

    let limiter = Arc::new(NativeBlockBodySendLimiter::default());
    let peer = [0xa1; 32];
    let now = Instant::now();
    let mut first = limiter
        .try_acquire_and_reserve(peer, now)
        .expect("first maximum-body reservation");
    assert!(first.commit_actual(MAX_NATIVE_BLOCK_META_BYTES));
    drop(first);
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    assert!(
        limiter.try_acquire_and_reserve(peer, now).is_none(),
        "second maximum-body request is rejected before materialization"
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        0
    );
}

#[tokio::test(flavor = "current_thread")]
async fn repeated_best_announce_reuses_cached_payload_without_body_reencoding() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let (_temp, node) = transport_test_node("best-announce-cache-test");
    let mut cache = NativeBestAnnounceCache::default();
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let first = native_best_announce_payload(&node, &mut cache)
        .await
        .expect("first best announce");
    let second = native_best_announce_payload(&node, &mut cache)
        .await
        .expect("cached best announce");
    assert_eq!(first, second);
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        1
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        1
    );
}

#[test]
fn scalar_best_tip_access_never_clones_or_encodes_a_maximum_body() {
    let _counter_guard = TRANSPORT_COUNTER_TEST_LOCK
        .lock()
        .expect("counter test lock");
    let (_temp, node) = transport_test_node("scalar-best-tip-test");

    node.reset_best_meta_clone_invocations();
    let _ = node.best_meta();
    assert_eq!(node.best_meta_clone_invocations(), 1, "counter control");

    node.state.write().best.action_bytes = vec![vec![0x5c; MAX_NATIVE_BLOCK_META_BYTES]];
    node.reset_best_meta_clone_invocations();
    NATIVE_BLOCK_BODY_HASH_INVOCATIONS.store(0, Ordering::Relaxed);
    NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.store(0, Ordering::Relaxed);
    let expected = node.best_tip();
    let expected_fork_choice = node.best_fork_choice_tip();
    for _ in 0..256 {
        assert_eq!(node.best_height(), expected.0);
        assert_eq!(node.best_tip(), expected);
        assert_eq!(node.best_fork_choice_tip(), expected_fork_choice);
    }
    node.observe_verified_sync_peer_height(expected.0);
    let snapshot = node.sync_target_evidence_snapshot();
    let state = node.state.read();
    assert!(node.sync_target_resolved_against_best(&state.best, snapshot.height, snapshot.hash));
    drop(state);
    assert!(node.catching_up_to_sync_target().is_none());
    assert!(!node.sync_status_fields().0);
    assert!(!node.clear_unanchored_sync_target_to_local_tip(
        expected.0,
        "scalar accessor transport regression",
    ));
    assert!(!node.clear_hash_anchored_sync_target_to_local_tip(
        expected.0,
        expected.1,
        "scalar accessor transport regression",
    ));
    assert_eq!(
        node.best_meta_clone_invocations(),
        0,
        "scalar access must not deep-clone the maximum-size action body"
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_SERIALIZE_INVOCATIONS.load(Ordering::Relaxed),
        0
    );
    assert_eq!(
        NATIVE_BLOCK_BODY_HASH_INVOCATIONS.load(Ordering::Relaxed),
        0
    );
}

#[test]
fn max_size_128_block_range_retains_and_hashes_only_one_body_prefix() {
    let mut retained = 0usize;
    let mut retained_peak = 0usize;
    let mut transient_peak = 0usize;
    let mut loaded = 0usize;
    let mut admitted = 0usize;
    for body_budget in std::iter::repeat(MAX_NATIVE_BLOCK_META_BYTES).take(128) {
        loaded += 1;
        transient_peak = transient_peak.max(
            retained
                .checked_add(body_budget)
                .expect("simulated transient byte total"),
        );
        let Some(next) =
            native_sync_response_materialization_next(retained, body_budget, admitted > 0)
                .expect("range materialization decision")
        else {
            break;
        };
        retained = next;
        retained_peak = retained_peak.max(retained);
        admitted += 1;
    }
    assert_eq!(admitted, 1, "only one maximum body is retained");
    assert_eq!(
        loaded, 2,
        "one rejected transient row proves the peak bound"
    );
    assert_eq!(retained_peak, MAX_NATIVE_BLOCK_META_BYTES);
    assert_eq!(transient_peak, MAX_NATIVE_BLOCK_META_BYTES * 2);
    assert_eq!(
        admitted, 1,
        "locator construction hashes only the admitted one-block prefix"
    );
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockBodyChunkTransportVectorFile {
    schema_version: u32,
    constants: LeanBlockBodyChunkTransportConstants,
    locator_cases: Vec<LeanBlockBodyLocatorCase>,
    chunk_cases: Vec<LeanBlockBodyChunkCase>,
    registration_cases: Vec<LeanBlockBodyRegistrationCase>,
    push_cases: Vec<LeanBlockBodyPushCase>,
    completion_cases: Vec<LeanBlockBodyCompletionCase>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockBodyChunkTransportConstants {
    body_schema_version: u16,
    chunk_bytes: usize,
    max_body_bytes: usize,
    max_chunk_count: usize,
    max_reassemblies_per_peer: usize,
    max_reassemblies_global: usize,
    max_reserved_bytes: usize,
    body_hash_domain_bytes: Vec<u8>,
    sample_body_bytes: Vec<u8>,
    sample_hash_preimage_bytes: Vec<u8>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockBodyLocatorCase {
    name: String,
    schema_matches: bool,
    chain_id_matches: bool,
    rules_hash_matches: bool,
    total_len: usize,
    declared_chunk_count: usize,
    expected_chunk_count: Option<usize>,
    expected_rejection: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockBodyChunkCase {
    name: String,
    total_len: usize,
    declared_chunk_count: usize,
    chunk_index: usize,
    declared_chunk_len: usize,
    actual_chunk_len: usize,
    expected_chunk_len: Option<usize>,
    expected_rejection: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockBodyRegistrationCase {
    name: String,
    locator_valid: bool,
    existing_same: bool,
    existing_conflict: bool,
    peer_entries: usize,
    global_entries: usize,
    reserved_bytes: usize,
    incoming_total_len: usize,
    expected_registered: Option<bool>,
    expected_rejection: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockBodyPushCase {
    name: String,
    chunk_valid: bool,
    requested: bool,
    locator_matches: bool,
    duplicate_present: bool,
    duplicate_bytes_match: bool,
    received_bytes: usize,
    incoming_bytes: usize,
    declared_total_len: usize,
    expected_received_bytes: Option<usize>,
    expected_rejection: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LeanBlockBodyCompletionCase {
    name: String,
    received_length_matches: bool,
    reassembled_length_matches: bool,
    body_hash_matches: bool,
    bincode_budget_accepts: bool,
    exact_decode_consumes_all: bool,
    canonical_reencode_matches: bool,
    locator_metadata_matches: bool,
    expected_rejection: Option<String>,
}

fn lean_block_body_locator(case: &LeanBlockBodyLocatorCase) -> NativeBlockBodyLocator {
    NativeBlockBodyLocator {
        schema_version: if case.schema_matches {
            NATIVE_BLOCK_BODY_SCHEMA_VERSION
        } else {
            NATIVE_BLOCK_BODY_SCHEMA_VERSION.wrapping_add(1)
        },
        chain_id: if case.chain_id_matches {
            HEGEMON_CHAIN_ID_V1
        } else {
            [0xf1; 32]
        },
        rules_hash: if case.rules_hash_matches {
            HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE
        } else {
            [0xf2; 32]
        },
        height: 1,
        block_hash: [0x31; 32],
        parent_hash: [0x30; 32],
        cumulative_work: [0x01; 48],
        total_len: u64::try_from(case.total_len).expect("Lean locator length fits u64"),
        body_hash: [0x32; 32],
        chunk_count: u32::try_from(case.declared_chunk_count)
            .expect("Lean locator chunk count fits u32"),
    }
}

fn native_block_body_locator_rejection_label(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("unsupported native block body schema version") {
        "schema_version"
    } else if message.contains("locator chain id mismatch") {
        "chain_id"
    } else if message.contains("locator rules hash mismatch") {
        "rules_hash"
    } else if message.contains("native block body must not be empty") {
        "total_len_empty"
    } else if message.contains("native block body exceeds canonical metadata limit") {
        "total_len_too_large"
    } else if message.contains("chunk count") {
        "chunk_count"
    } else {
        panic!("unclassified native block body locator rejection: {message}")
    }
}

fn native_block_body_chunk_rejection_label(error: &anyhow::Error) -> &'static str {
    let message = error.to_string();
    if message.contains("native block body must not be empty") {
        "total_len_empty"
    } else if message.contains("native block body exceeds canonical metadata limit") {
        "total_len_too_large"
    } else if message.contains("chunk count") {
        "chunk_count"
    } else if message.contains("chunk index out of range") {
        "chunk_index"
    } else if message.contains("chunk payload exceeds limit") {
        "payload_too_large"
    } else if message.contains("chunk length mismatch") {
        "chunk_length"
    } else {
        panic!("unclassified native block body chunk rejection: {message}")
    }
}

fn evaluate_lean_block_body_registration_case(
    case: &LeanBlockBodyRegistrationCase,
) -> std::result::Result<bool, &'static str> {
    if !case.locator_valid {
        Err("locator")
    } else if case.existing_same {
        Ok(false)
    } else if case.existing_conflict {
        Err("conflicting_locator")
    } else if case.peer_entries >= MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_PER_PEER {
        Err("per_peer_limit")
    } else if case.global_entries >= MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL {
        Err("global_limit")
    } else {
        let next_reserved = case
            .reserved_bytes
            .checked_add(case.incoming_total_len)
            .ok_or("reserved_byte_overflow")?;
        if next_reserved > MAX_NATIVE_BLOCK_BODY_REASSEMBLY_RESERVED_BYTES {
            Err("reserved_byte_limit")
        } else {
            Ok(true)
        }
    }
}

fn evaluate_lean_block_body_push_case(
    case: &LeanBlockBodyPushCase,
) -> std::result::Result<usize, &'static str> {
    if !case.chunk_valid {
        Err("chunk")
    } else if !case.requested {
        Err("unsolicited")
    } else if !case.locator_matches {
        Err("locator_conflict")
    } else if case.duplicate_present {
        if case.duplicate_bytes_match {
            Err("duplicate")
        } else {
            Err("conflicting_duplicate")
        }
    } else {
        let next_received = case
            .received_bytes
            .checked_add(case.incoming_bytes)
            .ok_or("received_byte_overflow")?;
        if next_received > case.declared_total_len {
            Err("received_bytes_exceed_total")
        } else {
            Ok(next_received)
        }
    }
}

fn evaluate_lean_block_body_completion_case(
    case: &LeanBlockBodyCompletionCase,
) -> std::result::Result<(), &'static str> {
    if !case.received_length_matches {
        Err("received_length")
    } else if !case.reassembled_length_matches {
        Err("reassembled_length")
    } else if !case.body_hash_matches {
        Err("body_hash")
    } else if !case.bincode_budget_accepts {
        Err("bincode_budget")
    } else if !case.exact_decode_consumes_all {
        Err("exact_decode")
    } else if !case.canonical_reencode_matches {
        Err("canonical_reencode")
    } else if !case.locator_metadata_matches {
        Err("locator_metadata")
    } else {
        Ok(())
    }
}

#[test]
fn lean_generated_block_body_chunk_transport_admission_vectors_match_production() {
    let Ok(path) = std::env::var("HEGEMON_LEAN_BLOCK_BODY_CHUNK_TRANSPORT_ADMISSION_VECTORS")
    else {
        eprintln!(
            "HEGEMON_LEAN_BLOCK_BODY_CHUNK_TRANSPORT_ADMISSION_VECTORS not set; skipping generated Lean vector check"
        );
        return;
    };
    let raw = std::fs::read_to_string(&path)
        .expect("read generated Lean block-body chunk transport admission vectors");
    let vectors: LeanBlockBodyChunkTransportVectorFile = serde_json::from_str(&raw)
        .expect("parse generated Lean block-body chunk transport admission vectors");
    assert_eq!(vectors.schema_version, 1);
    let constants = &vectors.constants;
    assert_eq!(
        constants.body_schema_version,
        NATIVE_BLOCK_BODY_SCHEMA_VERSION
    );
    assert_eq!(constants.chunk_bytes, MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES);
    assert_eq!(constants.max_body_bytes, MAX_NATIVE_BLOCK_META_BYTES);
    assert_eq!(constants.max_chunk_count, MAX_NATIVE_BLOCK_BODY_CHUNKS);
    assert_eq!(
        constants.max_reassemblies_per_peer,
        MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_PER_PEER
    );
    assert_eq!(
        constants.max_reassemblies_global,
        MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL
    );
    assert_eq!(
        constants.max_reserved_bytes,
        MAX_NATIVE_BLOCK_BODY_REASSEMBLY_RESERVED_BYTES
    );
    assert_eq!(
        constants.body_hash_domain_bytes,
        b"hegemon-native-block-body-v3\0"
    );
    let mut expected_preimage = constants.body_hash_domain_bytes.clone();
    expected_preimage.extend_from_slice(
        &u64::try_from(constants.sample_body_bytes.len())
            .expect("sample body length fits u64")
            .to_le_bytes(),
    );
    expected_preimage.extend_from_slice(&constants.sample_body_bytes);
    assert_eq!(expected_preimage, constants.sample_hash_preimage_bytes);
    let mut sample_hasher = blake3::Hasher::new();
    sample_hasher.update(&constants.body_hash_domain_bytes);
    sample_hasher.update(
        &u64::try_from(constants.sample_body_bytes.len())
            .expect("sample body length fits u64")
            .to_le_bytes(),
    );
    sample_hasher.update(&constants.sample_body_bytes);
    assert_eq!(
        native_block_body_hash(&constants.sample_body_bytes),
        *sample_hasher.finalize().as_bytes()
    );

    let mut names = std::collections::BTreeSet::new();
    for case in &vectors.locator_cases {
        assert!(names.insert(format!("locator:{}", case.name)));
        let actual = validate_native_block_body_locator(&lean_block_body_locator(case));
        assert_eq!(
            actual
                .as_ref()
                .err()
                .map(native_block_body_locator_rejection_label),
            case.expected_rejection.as_deref(),
            "{} locator rejection drifted from Lean spec",
            case.name
        );
        let actual_chunk_count = actual.as_ref().ok().map(|total_len| {
            assert_eq!(
                *total_len, case.total_len,
                "{} validated locator length drifted from Lean spec",
                case.name
            );
            usize::try_from(
                native_block_body_chunk_count(*total_len)
                    .expect("validated locator has a native chunk count"),
            )
            .expect("native chunk count fits usize")
        });
        assert_eq!(
            actual_chunk_count, case.expected_chunk_count,
            "{} locator chunk count drifted from Lean spec",
            case.name
        );
    }

    for case in &vectors.chunk_cases {
        assert!(names.insert(format!("chunk:{}", case.name)));
        let chunk = NativeBlockBodyChunk {
            block_hash: [0x41; 32],
            total_len: u64::try_from(case.total_len).expect("Lean chunk total fits u64"),
            body_hash: [0x42; 32],
            chunk_index: u32::try_from(case.chunk_index).expect("Lean chunk index fits u32"),
            chunk_count: u32::try_from(case.declared_chunk_count)
                .expect("Lean chunk count fits u32"),
            chunk_len: u32::try_from(case.declared_chunk_len)
                .expect("Lean declared chunk length fits u32"),
            bytes: vec![0x43; case.actual_chunk_len],
        };
        let actual = validate_native_block_body_chunk(&chunk);
        assert_eq!(
            actual
                .as_ref()
                .err()
                .map(native_block_body_chunk_rejection_label),
            case.expected_rejection.as_deref(),
            "{} chunk rejection drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_chunk_len,
            "{} chunk length drifted from Lean spec",
            case.name
        );
    }

    for case in &vectors.registration_cases {
        assert!(names.insert(format!("registration:{}", case.name)));
        let actual = evaluate_lean_block_body_registration_case(case);
        assert_eq!(
            actual.as_ref().err().copied(),
            case.expected_rejection.as_deref(),
            "{} registration rejection precedence drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_registered,
            "{} registration result drifted from Lean spec",
            case.name
        );
    }

    for case in &vectors.push_cases {
        assert!(names.insert(format!("push:{}", case.name)));
        let actual = evaluate_lean_block_body_push_case(case);
        assert_eq!(
            actual.as_ref().err().copied(),
            case.expected_rejection.as_deref(),
            "{} push rejection precedence drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.ok(),
            case.expected_received_bytes,
            "{} received-byte result drifted from Lean spec",
            case.name
        );
    }

    for case in &vectors.completion_cases {
        assert!(names.insert(format!("completion:{}", case.name)));
        let actual = evaluate_lean_block_body_completion_case(case);
        assert_eq!(
            actual.as_ref().err().copied(),
            case.expected_rejection.as_deref(),
            "{} completion rejection precedence drifted from Lean spec",
            case.name
        );
        assert_eq!(
            actual.is_ok(),
            case.expected_rejection.is_none(),
            "{} completion validity drifted from Lean spec",
            case.name
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn bounded_sync_range_loader_queue_caps_32_and_64_peer_materialization_and_stays_live() {
    for peer_count in [32usize, MAX_NATIVE_SYNC_RANGE_LOAD_QUEUE] {
        let mut queue = NativeSyncRangeLoadQueue::default();
        let mut peers = Vec::with_capacity(peer_count);
        for index in 0..peer_count {
            let mut peer_id = [0u8; 32];
            peer_id[..8].copy_from_slice(
                &u64::try_from(index)
                    .expect("peer index fits u64")
                    .to_le_bytes(),
            );
            peers.push(peer_id);
            queue
                .admit(
                    peer_id,
                    NativeSyncRange {
                        from_height: u64::try_from(index).expect("range index fits u64"),
                        to_height: u64::try_from(index).expect("range index fits u64"),
                    },
                )
                .expect("metadata-only range queue admission");
        }
        assert_eq!(queue.outstanding(), peer_count);
        assert_eq!(
            queue
                .admit(
                    peers[0],
                    NativeSyncRange {
                        from_height: 1000,
                        to_height: 1000,
                    },
                )
                .expect_err("one outstanding range per peer"),
            NativeSyncRangeLoadAdmissionRejection::PeerOutstanding
        );
        if peer_count == MAX_NATIVE_SYNC_RANGE_LOAD_QUEUE {
            assert_eq!(
                queue
                    .admit(
                        [0xff; 32],
                        NativeSyncRange {
                            from_height: 2000,
                            to_height: 2000,
                        },
                    )
                    .expect_err("bounded global metadata queue"),
                NativeSyncRangeLoadAdmissionRejection::QueueFull
            );
        }

        let mut active = VecDeque::new();
        for expected_peer in peers.iter().take(MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT) {
            let (started_peer, _) = queue
                .pop_next_for_test()
                .expect("global loader slot must start");
            assert_eq!(&started_peer, expected_peer, "FIFO peer fairness");
            active.push_back(started_peer);
        }
        assert!(
            queue.pop_next_for_test().is_none(),
            "a held third loader must not reach block_range"
        );
        assert_eq!(queue.active(), MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT);
        assert_eq!(
            queue.reserved_bytes(),
            MAX_NATIVE_SYNC_RANGE_LOAD_RESERVED_BYTES,
            "retained-plus-transient body bytes must be reserved before loading"
        );
        assert_eq!(
            queue.waiting(),
            peer_count - MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT
        );

        tokio::time::timeout(
            Duration::from_millis(250),
            tokio::time::sleep(Duration::from_millis(1)),
        )
        .await
        .expect("Tokio heartbeat must progress while loader slots are held");

        let mut started = MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT;
        while let Some(completed_peer) = active.pop_front() {
            queue.finish_for_test(completed_peer);
            if let Some((next_peer, _)) = queue.pop_next_for_test() {
                assert_eq!(next_peer, peers[started], "FIFO peer fairness drifted");
                started = started.saturating_add(1);
                active.push_back(next_peer);
            }
            assert!(queue.active() <= MAX_NATIVE_SYNC_RANGE_LOADS_IN_FLIGHT);
            assert!(queue.reserved_bytes() <= MAX_NATIVE_SYNC_RANGE_LOAD_RESERVED_BYTES);
        }
        assert_eq!(
            started, peer_count,
            "every honest queued peer must progress"
        );
        assert_eq!(queue.active(), 0);
        assert_eq!(queue.waiting(), 0);
        assert_eq!(queue.outstanding(), 0);
        assert_eq!(queue.reserved_bytes(), 0);
    }

    let (_temp, node) = transport_test_node("range-loader-heartbeat-test");
    let mut cache = NativeBestAnnounceCache::default();
    tokio::time::timeout(
        Duration::from_secs(2),
        native_best_announce_payload(&node, &mut cache),
    )
    .await
    .expect("best announce must progress independently of range workers")
    .expect("encode best announce while range workers are bounded");
}
