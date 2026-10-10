use super::*;
use serde::Deserialize;

const BITS: u32 = 0x1d04_2241;

fn schedule(
    height: u64,
    elapsed_ms: Option<u64>,
    activation: Option<u64>,
) -> Result<u32, ConsensusError> {
    expected_pow_bits_from_schedule_with_activation(
        GENESIS_BITS,
        BITS,
        height.saturating_sub(1),
        height,
        9_000_000,
        elapsed_ms.map(|elapsed| 9_000_000 - elapsed),
        activation,
    )
}

#[test]
fn retarget_activation_selects_ten_intervals_only_at_eligible_heights() {
    for height in [0, 1, 9, 10, 11, 19, 21, 29, 31, 39, u64::MAX] {
        assert_eq!(
            pow_retarget_anchor_steps_with_activation(height.saturating_sub(1), height, Some(30)),
            None
        );
    }
    for (height, steps) in [(20, 9), (30, 10), (40, 10), (120_000, 10)] {
        assert_eq!(
            pow_retarget_anchor_steps_with_activation(height - 1, height, Some(30)),
            Some(steps)
        );
        assert_eq!(
            pow_retarget_anchor_steps_with_activation(height - 1, height, None),
            Some(9)
        );
    }
    // A non-boundary threshold never changes inherited bits early.
    assert_eq!(schedule(25, None, Some(25)).unwrap(), BITS);
    assert_eq!(
        pow_retarget_anchor_steps_with_activation(29, 30, Some(25)),
        Some(10)
    );
    assert_eq!(schedule(0, None, Some(30)).unwrap(), GENESIS_BITS);
    assert_eq!(schedule(10, Some(8_000_000), Some(10)).unwrap(), BITS);
}

#[test]
fn retarget_activation_corrects_sixty_second_cadence_without_changing_clamps() {
    let target = compact_to_target(BITS).unwrap();
    // Legacy samples nine gaps even when every gap is exactly sixty seconds.
    assert_eq!(
        schedule(20, Some(540_000), Some(30)).unwrap(),
        target_to_compact(&(&target * 9u32 / 10u32))
    );
    assert_ne!(schedule(20, Some(540_000), Some(30)).unwrap(), BITS);
    assert_eq!(schedule(30, Some(600_000), Some(30)).unwrap(), BITS);
    assert_eq!(schedule(40, Some(600_000), Some(30)).unwrap(), BITS);
    for (elapsed, numerator, denominator) in [
        (0, 1u32, 4u32),
        (149_999, 1, 4),
        (150_000, 1, 4),
        (300_000, 1, 2),
        (600_000, 1, 1),
        (1_200_000, 2, 1),
        (2_400_000, 4, 1),
        (8_000_000, 4, 1),
    ] {
        assert_eq!(
            schedule(30, Some(elapsed), Some(30)).unwrap(),
            target_to_compact(&(&target * numerator / denominator))
        );
    }
    assert!(schedule(30, None, Some(30)).is_err());
    assert_eq!(schedule(31, None, Some(30)).unwrap(), BITS);
}

#[derive(Deserialize)]
struct LiveFixture {
    genesis_hash: String,
    cases: Vec<LiveCase>,
}
#[derive(Deserialize)]
struct LiveCase {
    height: u64,
    parent_bits: u32,
    actual_bits: u32,
    parent_timestamp_ms: u64,
    legacy_anchor_timestamp_ms: u64,
    corrected_anchor_timestamp_ms: u64,
}

#[test]
fn retarget_activation_preserves_all_145_sampled_testnet_adjustments() {
    let fixture: LiveFixture = serde_json::from_str(include_str!(
        "../../tests/fixtures/testnet_retarget_20261010.json"
    ))
    .unwrap();
    assert_eq!(
        fixture.genesis_hash,
        "0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59"
    );
    assert_eq!(fixture.cases.len(), 145);
    for case in fixture.cases {
        for activation in [None, Some(120_000)] {
            assert_eq!(
                expected_pow_bits_from_schedule_with_activation(
                    GENESIS_BITS,
                    case.parent_bits,
                    case.height - 1,
                    case.height,
                    case.parent_timestamp_ms,
                    Some(case.legacy_anchor_timestamp_ms),
                    activation,
                )
                .unwrap(),
                case.actual_bits,
                "legacy chain changed at {}",
                case.height
            );
        }
        let elapsed = case.parent_timestamp_ms - case.corrected_anchor_timestamp_ms;
        let target = compact_to_target(case.parent_bits).unwrap();
        // Independently reproduce fixed rule integer arithmetic from public data.
        let corrected_target = (&target * elapsed.clamp(150_000, 2_400_000)) / 600_000u64;
        assert_eq!(
            expected_pow_bits_from_schedule_with_activation(
                GENESIS_BITS,
                case.parent_bits,
                case.height - 1,
                case.height,
                case.parent_timestamp_ms,
                Some(case.corrected_anchor_timestamp_ms),
                Some(20),
            )
            .unwrap(),
            target_to_compact(&corrected_target)
        );
    }
}
