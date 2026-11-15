//! Consensus vectors for the additive time-rolling profile. These verify exact
//! work binding and historical schedule preservation, not hardware behavior.

use super::*;

fn header(rules_hash: Hash32, timestamp_ms: u64) -> PowHeaderV2 {
    PowHeaderV2 {
        chain_id: [1; 32],
        rules_hash,
        height: 180,
        timestamp_ms,
        parent_hash: [2; 32],
        state_root: [3; 48],
        kernel_root: [4; 48],
        nullifier_root: [5; 48],
        proof_commitment: [6; 48],
        da_root: [7; 48],
        action_root: [8; 32],
        tx_statements_commitment: [9; 48],
        version_commitment: if is_combined_rules(&rules_hash) {
            bitcoin80_mining_version_payload(BITCOIN80_VERSION)
        } else {
            [0; 48]
        },
        fee_commitment: [11; 48],
        supply_digest: 12,
        tx_count: 13,
        message_root: [14; 48],
        message_count: 15,
        header_mmr_root: [16; 32],
        header_mmr_len: 180,
        pow_bits: 0x207fffff,
        nonce: [17; 32],
        cumulative_work: [18; 48],
    }
}

fn exact80(header: &PowHeaderV2) -> [u8; 80] {
    bitcoin80_header_with_version(
        &header.pre_hash(),
        &header.parent_hash,
        header.timestamp_ms,
        header.pow_bits,
        header.nonce,
        header.mining_version().unwrap(),
    )
    .unwrap()
}

fn solve(header: &mut PowHeaderV2) {
    for nonce in 0u32..1_000 {
        header.nonce[..4].copy_from_slice(&nonce.to_le_bytes());
        if hash_meets_target(&header.pow_hash(), header.pow_bits).unwrap() {
            return;
        }
    }
    panic!("easy fixture must mine");
}

#[test]
fn time_rolling_profile_hash_and_inheritance_are_exact() {
    assert_eq!(
        hash32(HEGEMON_LIGHT_CLIENT_RULES_BITCOIN_TIME_ROLLING_PREIMAGE),
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING
    );
    let rules = HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING;
    assert!(is_time_rolling_rules(&rules));
    assert!(is_combined_rules(&rules));
    assert!(is_asert_rules(&rules));
    assert!(is_bitcoin80_rules(&rules));
    for old in [
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED,
    ] {
        assert_ne!(rules, old);
        assert!(!is_time_rolling_rules(&old));
    }
}

#[test]
fn time_rolling_schedule_preserves_combined_origin_and_all_prior_rules() {
    let combined = PowRulesSchedule::combined_at(120).unwrap();
    let upgraded = PowRulesSchedule::combined_with_time_rolling_at(120, 180).unwrap();
    assert_eq!(upgraded.asert_activation_height(), Some(120));
    assert_eq!(upgraded.time_rolling_activation_height(), Some(180));
    for height in 0..180 {
        assert_eq!(upgraded.rules_hash(height), combined.rules_hash(height));
    }
    for height in [180, 181, u64::MAX] {
        assert_eq!(
            upgraded.rules_hash(height),
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING
        );
    }
    for (combined, time) in [(0, 180), (1, 180), (119, 180), (120, 119), (120, 120)] {
        assert_eq!(
            PowRulesSchedule::combined_with_time_rolling_at(combined, time),
            Err(LightClientError::InvalidPowRulesSchedule)
        );
    }
    let chain = PREMAINNET_CHAIN_ID;
    let activation = PREMAINNET_TIME_ROLLING_ACTIVATION_HEIGHT.unwrap();
    assert!(activation > 18_660);
    assert_eq!(
        native_pow_rules(&chain).asert_activation_height(),
        Some(18_660)
    );
    assert_eq!(
        native_combined_upgrade_activation_height(&chain),
        Some(18_660)
    );
    assert_eq!(
        native_time_rolling_activation_height(&chain),
        Some(activation)
    );
    assert!(!native_time_rolling_active(&chain, activation - 1));
    assert!(native_time_rolling_active(&chain, activation));
    assert!(!native_time_rolling_active(&[0x55; 32], u64::MAX));
    assert_eq!(native_time_rolling_activation_height(&[0x55; 32]), None);
    #[cfg(feature = "combined-upgrade-rehearsal")]
    {
        assert_eq!(
            native_time_rolling_activation_height(&COMBINED_REHEARSAL_CHAIN_ID),
            Some(180)
        );
        assert_eq!(native_pow_rules(&COMBINED_REHEARSAL_CHAIN_ID), upgraded);
    }
    #[cfg(not(feature = "combined-upgrade-rehearsal"))]
    assert_eq!(
        native_time_rolling_activation_height(&COMBINED_REHEARSAL_CHAIN_ID),
        None
    );
}

#[test]
fn backward_and_forward_time_rolling_keep_coinbase_and_bind_exact_header_time() {
    let base = header(
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING,
        1_700_000_060_000,
    );
    let original = exact80(&base);
    for timestamp in [
        1_700_000_000_000,
        1_700_000_059_000,
        1_700_000_061_000,
        1_700_000_130_000,
    ] {
        let mut rolled = base.clone();
        rolled.timestamp_ms = timestamp;
        let bytes = exact80(&rolled);
        assert_ne!(rolled.canonical_bytes(), base.canonical_bytes());
        assert_eq!(rolled.pre_hash(), base.pre_hash());
        assert_eq!(&bytes[..68], &original[..68]);
        assert_eq!(&bytes[72..], &original[72..]);
        assert_eq!(
            &bytes[68..72],
            &(timestamp as u64 / 1000).to_le_bytes()[..4]
        );
        assert_ne!(bytes, original);
        assert_eq!(rolled.pow_hash(), bitcoin80_hash_header(&bytes));
        assert_ne!(rolled.pow_hash(), base.pow_hash());
    }
    let mut version = base.clone();
    version.version_commitment = bitcoin80_mining_version_payload(BITCOIN80_VERSION | 0x20);
    assert_eq!(version.pre_hash(), base.pre_hash());
    assert_ne!(version.pow_hash(), base.pow_hash());
}

#[test]
fn time_rolling_rejects_precision_overflow_and_malformed_version_aliases() {
    let rules = HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING;
    for timestamp in [0, 1000, u64::from(u32::MAX) * 1000] {
        assert_eq!(
            bitcoin80_validate_timestamp_for_rules(&rules, timestamp),
            Ok((timestamp / 1000) as u32)
        );
    }
    for timestamp in [1, 999, 1001, u64::from(u32::MAX) * 1000 + 999] {
        assert_eq!(
            bitcoin80_validate_timestamp_for_rules(&rules, timestamp),
            Err(LightClientError::TimestampNotWholeSecond)
        );
        assert_eq!(header(rules, timestamp).pow_hash(), [0xff; 32]);
    }
    for timestamp in [(u64::from(u32::MAX) + 1) * 1000, u64::MAX] {
        assert_eq!(
            bitcoin80_validate_timestamp_for_rules(&rules, timestamp),
            Err(LightClientError::TimestampOutOfRange)
        );
    }
    let valid = header(rules, 1_700_000_000_000);
    for index in [0, 4, 47] {
        let mut malformed = valid.clone();
        malformed.version_commitment[index] ^= 1;
        assert_eq!(
            malformed.mining_version(),
            Err(LightClientError::InvalidMiningVersion)
        );
        assert_ne!(malformed.pre_hash(), valid.pre_hash());
        assert_eq!(malformed.pow_hash(), [0xff; 32]);
    }
    let mut state_mutation = valid.clone();
    state_mutation.state_root[0] ^= 1;
    assert_ne!(state_mutation.pre_hash(), valid.pre_hash());
    assert_ne!(&exact80(&state_mutation)[36..68], &exact80(&valid)[36..68]);
}

#[test]
fn historical_timestamp_commitments_keep_their_exact_preimage() {
    for rules in [
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT,
        HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED,
    ] {
        let old = header(rules, 1_700_000_000_123);
        let mut expected = old.clone();
        if is_combined_rules(&rules) {
            expected.version_commitment = [0; 48];
        }
        assert_eq!(old.pre_hash(), hash32(&expected.canonical_bytes()));
        let mut changed = old.clone();
        changed.timestamp_ms += 1;
        assert_ne!(changed.pre_hash(), old.pre_hash());
        assert_ne!(changed.pow_hash(), old.pow_hash());
        assert!(bitcoin80_validate_timestamp_for_rules(&rules, changed.timestamp_ms).is_ok());
    }
}

#[test]
fn rolled_time_can_precede_job_time_but_must_follow_full_parent_time() {
    let schedule = PowRulesSchedule::combined_with_time_rolling_at(120, 180).unwrap();
    let parent = TrustedCheckpointV2 {
        chain_id: [1; 32],
        rules_hash: schedule.rules_hash(179),
        height: 179,
        header_hash: [2; 32],
        // The last historical block may carry a millisecond timestamp.
        timestamp_ms: 1_700_000_000_999,
        pow_bits: 0x207fffff,
        cumulative_work: [0; 48],
        header_mmr_root: [0; 32],
        header_mmr_len: 179,
    };
    let mut job = header(schedule.rules_hash(180), 1_700_000_061_000);
    job.cumulative_work = cumulative_work_after(&parent.cumulative_work, job.pow_bits).unwrap();
    let mut earlier = job.clone();
    earlier.timestamp_ms -= 60_000;
    assert_eq!(earlier.pre_hash(), job.pre_hash());
    for candidate in [&mut job, &mut earlier] {
        solve(candidate);
        assert_eq!(
            verify_pow_header_v2_with_expected_bits_and_schedule(
                &parent,
                candidate,
                parent.pow_bits,
                schedule
            ),
            Ok(candidate.pow_hash())
        );
    }
    let mut before_parent = earlier.clone();
    before_parent.timestamp_ms = 1_700_000_000_000;
    assert_eq!(
        verify_pow_header_v2_with_expected_bits_and_schedule(
            &parent,
            &before_parent,
            parent.pow_bits,
            schedule
        ),
        Err(LightClientError::TimestampDidNotAdvance)
    );
    let mut at_parent = earlier;
    at_parent.timestamp_ms = parent.timestamp_ms;
    assert_eq!(
        verify_pow_header_v2_with_expected_bits_and_schedule(
            &parent,
            &at_parent,
            parent.pow_bits,
            schedule
        ),
        Err(LightClientError::TimestampDidNotAdvance)
    );
}

#[test]
fn time_rolling_transition_authenticates_both_endpoints_and_replay() {
    let schedule = PowRulesSchedule::combined_with_time_rolling_at(120, 180).unwrap();
    let mut checkpoint = TrustedCheckpointV2 {
        chain_id: [1; 32],
        rules_hash: schedule.rules_hash(178),
        height: 178,
        header_hash: [2; 32],
        timestamp_ms: 1_700_000_000_123,
        pow_bits: 0x207fffff,
        cumulative_work: [0; 48],
        header_mmr_root: [0; 32],
        header_mmr_len: 178,
    };
    let start = checkpoint.clone();
    let mut headers = Vec::new();
    for height in [179, 180, 181] {
        let mut next = header(
            schedule.rules_hash(height),
            1_700_000_001_000 + (height - 179) * 1000,
        );
        next.height = height;
        next.header_mmr_len = height;
        next.parent_hash = checkpoint.header_hash;
        next.cumulative_work =
            cumulative_work_after(&checkpoint.cumulative_work, next.pow_bits).unwrap();
        solve(&mut next);
        let verify = |parent: &TrustedCheckpointV2, child: &PowHeaderV2| {
            verify_pow_header_v2_with_expected_bits_and_schedule(
                parent,
                child,
                child.pow_bits,
                schedule,
            )
        };
        assert_eq!(verify(&checkpoint, &next), Ok(next.pow_hash()));
        let mut bad_parent = checkpoint.clone();
        bad_parent.rules_hash = if is_time_rolling_rules(&checkpoint.rules_hash) {
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED
        } else {
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING
        };
        assert_eq!(
            verify(&bad_parent, &next),
            Err(LightClientError::RulesHashMismatch)
        );
        let mut bad_child = next.clone();
        bad_child.rules_hash = if is_time_rolling_rules(&next.rules_hash) {
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED
        } else {
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING
        };
        assert_eq!(
            verify(&checkpoint, &bad_child),
            Err(LightClientError::RulesHashMismatch)
        );
        if height >= 180 {
            let mut precision = next.clone();
            precision.timestamp_ms += 1;
            assert_eq!(
                verify(&checkpoint, &precision),
                Err(LightClientError::TimestampNotWholeSecond)
            );
            let mut missing = next.clone();
            missing.version_commitment = [0; 48];
            assert_eq!(
                verify(&checkpoint, &missing),
                Err(LightClientError::InvalidMiningVersion)
            );
        }
        checkpoint = next.checkpoint();
        headers.push(next);
    }
    // Replay the exact same bytes independently from the initial checkpoint.
    let mut replay = start;
    for next in &headers {
        verify_pow_header_v2_with_expected_bits_and_schedule(
            &replay,
            next,
            next.pow_bits,
            schedule,
        )
        .unwrap();
        replay = next.checkpoint();
    }
    assert_eq!(replay, checkpoint);
}
