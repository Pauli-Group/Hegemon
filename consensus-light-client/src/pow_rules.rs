//! Source-owned difficulty upgrades, separate from immutable genesis identity.
//!
//! The manifest and original rules hash stay fixed. Header rules evolve only at
//! an explicitly compiled height for a specific chain; no local operator flag,
//! clock, peer announcement or manifest mutation can change that schedule.

#[cfg(any(feature = "asert-rehearsal", test))]
use crate::HEGEMON_CHAIN_ID_V1;
use crate::{Hash32, LightClientError, HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC};

pub const ASERT_TARGET_SPACING_MS: u64 = 60_000;
pub const ASERT_HALF_LIFE_MS: u64 = 3_600_000;
/// The v0.11.4 coordinated pre-mainnet activation is source-owned, never a
/// runtime configuration option.
pub const PREMAINNET_COMBINED_UPGRADE_ACTIVATION_HEIGHT: Option<u64> = Some(18_660);
/// Additive timestamp-rolling successor. The original combined boundary remains
/// the ASERT anchor and treasury cadence origin.
pub const PREMAINNET_TIME_ROLLING_ACTIVATION_HEIGHT: Option<u64> = Some(28_860);
/// ASERT, mining version rolling and treasury cadence share one migration height.
pub const PREMAINNET_ASERT_ACTIVATION_HEIGHT: Option<u64> =
    PREMAINNET_COMBINED_UPGRADE_ACTIVATION_HEIGHT;
/// Exact disposable funded Development identity. Never selected without the
/// opt-in rehearsal build.
pub const COMBINED_REHEARSAL_CHAIN_ID: Hash32 = [
    0xa6, 0xdd, 0xd1, 0x81, 0x7d, 0x8c, 0x69, 0x87, 0xd5, 0x84, 0x21, 0x4e, 0xa5, 0xe3, 0x93, 0xcb,
    0xd0, 0xf9, 0x6d, 0x13, 0x8a, 0xcc, 0x0a, 0xa2, 0x16, 0xdb, 0x4f, 0x76, 0x18, 0xbe, 0x30, 0xf0,
];
pub const COMBINED_REHEARSAL_ACTIVATION_HEIGHT: u64 = 120;
pub const TIME_ROLLING_REHEARSAL_ACTIVATION_HEIGHT: u64 = 180;
/// Exact composed profile; activation height is selected separately below.
pub const HEGEMON_LIGHT_CLIENT_RULES_BITCOIN_COMBINED_PREIMAGE: &[u8] = b"hegemon.native.rules-bitcoin-combined-v1\nbase-asert-rules-hash=992a6a04c320f65fb55dd0576f01d174981e56b959fa50294bad7fffc333c205\npow-envelope=bitcoin80;fixed-bits=0x20000000;rolling-mask=0x1fffffe0\npow-version-commitment=u32le(version)||44byte-tag:hegemon.bitcoin80.mining-version-v1:9nul\npow-prehash=blake3(v2-canonical-header-without-nonce:713bytes;validated-version-commitment-zeroed)\npow-final-version=exact-u32le-version;sha256d-header-binds-rolling-bits\npow-extranonce=28bytes;split-is-adapter-only\nmetadata=hegemon-mining-metadata-v1:6nul||u32le(version)||legacy-bincode\nreward-treasury=hegemon-treasury-exact-per-height-1of5-60-blocks-independent-miner-claim-v1\nreward-accrual=sum(floor(scheduled-subsidy(h)/5));all-accepted-active-heights;no-historical-reaccrual\nreward-boundary=(height-activation)%60==59;positive-due-mandatory;zero-due-no-note\nreward-miner=scheduled-subsidy-floor(scheduled-subsidy/5)+fees;per-block;omission-forfeits-miner-only\nreward-treasury-recipient=existing-authorized-funding-recipient;action12-contextual-primary-or-secondary\nreward-issued-supply-digest=gross-actual-created-coinbase-note-values;recycled-fees-included;pending-entitlement-separate\nreward-maturity=creation-height+120;proof-geometry=unchanged-fixed-two-input-private-spend\nactivation=source-owned-chain-id-height-schedule;H>=2;H%60==0;genesis-identity-preserved";
pub const HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED: Hash32 = [
    0xec, 0x30, 0x45, 0x29, 0xf4, 0x9e, 0x7d, 0xdc, 0x77, 0x7e, 0x0c, 0xa7, 0x8b, 0x18, 0x9a, 0xce,
    0xc7, 0x53, 0xd4, 0xfb, 0x18, 0xaa, 0xfe, 0x15, 0x76, 0x1e, 0x68, 0x6e, 0xa3, 0x59, 0x6b, 0x7f,
];
/// The successor preserves the combined profile's proof, monetary, version,
/// target and original activation semantics. Only timestamp work binding and
/// canonical timestamp precision change; the final SHA256d header binds time.
pub const HEGEMON_LIGHT_CLIENT_RULES_BITCOIN_TIME_ROLLING_PREIMAGE: &[u8] = b"hegemon.native.rules-bitcoin-time-rolling-v1\nbase-combined-rules-hash=ec304529f49e7ddc777e0ca78b189acec753d4fb18aafe15761e686ea3596b7f\npow-prehash=blake3(v2-canonical-header-without-nonce:713bytes;validated-version-commitment-zeroed;timestamp-ms-zeroed)\npow-final-time=timestamp-ms/1000:u32le-at-header-bytes68..72;sha256d-header-binds-time\ntimestamp-canonical=whole-seconds;timestamp-ms%1000=0;timestamp-ms/1000<=u32max\ntimestamp-order=strictly-after-parent-native-timestamp-ms\ntimestamp-fresh-admission=local-now-ms+90000-inclusive;historical-replay-clock-independent\npow-version-and-target=combined-unchanged\nasert-anchor=original-combined-activation-H-1;reference-time=H-2;no-reset\nreward-treasury-cadence=original-combined-activation;no-reset\nproof-and-body=combined-unchanged\nactivation=source-owned-chain-id-height-schedule;after-combined;genesis-identity-preserved";
pub const HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING: Hash32 = [
    0xd5, 0xf9, 0x18, 0x74, 0xce, 0xa4, 0xe4, 0xea, 0xde, 0x6a, 0xc7, 0xf3, 0x1b, 0x2a, 0xda, 0x7a,
    0x29, 0x02, 0xe7, 0x1e, 0x06, 0x5d, 0x02, 0xa4, 0x76, 0xdc, 0x6e, 0x64, 0x6d, 0xa1, 0xa3, 0x8f,
];
pub const PREMAINNET_CHAIN_ID: Hash32 = [
    0x7b, 0x7b, 0x08, 0x99, 0xd5, 0x44, 0x4f, 0xfd, 0x92, 0xc3, 0x8b, 0x38, 0x18, 0x8e, 0x9c, 0xe4,
    0xf8, 0x91, 0x91, 0x3c, 0xa7, 0xcc, 0xa8, 0x54, 0xfd, 0xca, 0xe0, 0xaa, 0x22, 0xca, 0x1b, 0x49,
];
const _: () = if let Some(height) = PREMAINNET_ASERT_ACTIVATION_HEIGHT {
    assert!(
        height >= 2 && height % 60 == 0,
        "combined activation needs ASERT ancestors and a multiple-of-60 height"
    );
};
const _: () = if let Some(time_height) = PREMAINNET_TIME_ROLLING_ACTIVATION_HEIGHT {
    assert!(
        matches!(PREMAINNET_COMBINED_UPGRADE_ACTIVATION_HEIGHT, Some(combined) if time_height > combined),
        "time rolling must follow the original combined activation"
    );
};

/// The profile commits the arithmetic and anchor convention. Activation height
/// is selected independently by the source-owned per-chain schedule below.
pub const HEGEMON_LIGHT_CLIENT_RULES_BITCOIN_ASERT_PREIMAGE: &[u8] = b"hegemon.native.rules-bitcoin-asert-v1\nbase-rules-hash=a08fc9ec383eec2bff554c64085bed809160241b89cee84cf2c8f27170a7e41f\npow-envelope=bitcoin80-unchanged\npow-retarget=aserti3-absolute-anchor\npow-target-spacing-ms=60000\npow-half-life-ms=3600000\npow-anchor=last-legacy-block:H-1:height,target;reference-time=timestamp(H-2)\npow-evaluation=parent-height,parent-timestamp-ms;exponent=(time-delta-spacing*(height-delta+1))*65536/half-life\npow-exponent-division=signed-truncate-toward-zero;split=arithmetic-right-shift16-and-low16\npow-factor=65536+((195766423245049*f+971821376*f*f+5127*f*f*f+2^47)>>48)\npow-target=anchor-target*factor*2^(integral-exponent-16);floor;min-one;max-0x207fffff;bitcoin-positive-canonical-compact\npow-live-gap-recovery=none\nactivation=source-owned-chain-id-height-schedule;genesis-identity-preserved";
pub const HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT: Hash32 = [
    0x99, 0x2a, 0x6a, 0x04, 0xc3, 0x20, 0xf6, 0x5f, 0xb5, 0x5d, 0xd0, 0x57, 0x6f, 0x01, 0xd1, 0x74,
    0x98, 0x1e, 0x56, 0xb9, 0x59, 0xfa, 0x50, 0x29, 0x4b, 0xad, 0x7f, 0xff, 0xc3, 0x33, 0xc2, 0x05,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PowRulesSchedule {
    asert_activation_height: Option<u64>,
    combined_upgrade: bool,
    time_rolling_activation_height: Option<u64>,
}

impl PowRulesSchedule {
    pub const LEGACY: Self = Self {
        asert_activation_height: None,
        combined_upgrade: false,
        time_rolling_activation_height: None,
    };

    /// Construct a deterministic schedule, including for explicit test fixtures.
    /// Production uses `native_pow_rules`, never caller-supplied schedule data.
    pub const fn asert_at(height: u64) -> Result<Self, LightClientError> {
        if height < 2 {
            Err(LightClientError::InvalidPowRulesSchedule)
        } else {
            Ok(Self {
                asert_activation_height: Some(height),
                combined_upgrade: false,
                time_rolling_activation_height: None,
            })
        }
    }

    /// A single migration boundary for the combined candidate. Genesis launch
    /// initialization is separate because it has no H-1/H-2 anchor pair.
    pub const fn combined_at(height: u64) -> Result<Self, LightClientError> {
        if height < 2 || height % 60 != 0 {
            Err(LightClientError::InvalidPowRulesSchedule)
        } else {
            Ok(Self {
                asert_activation_height: Some(height),
                combined_upgrade: true,
                time_rolling_activation_height: None,
            })
        }
    }

    /// Add a later time-rolling boundary without changing the original ASERT
    /// anchor or the combined profile's monetary activation height.
    pub const fn combined_with_time_rolling_at(
        combined_height: u64,
        time_height: u64,
    ) -> Result<Self, LightClientError> {
        if combined_height < 2 || combined_height % 60 != 0 || time_height <= combined_height {
            Err(LightClientError::InvalidPowRulesSchedule)
        } else {
            Ok(Self {
                asert_activation_height: Some(combined_height),
                combined_upgrade: true,
                time_rolling_activation_height: Some(time_height),
            })
        }
    }

    pub const fn asert_activation_height(self) -> Option<u64> {
        self.asert_activation_height
    }

    pub const fn time_rolling_activation_height(self) -> Option<u64> {
        self.time_rolling_activation_height
    }

    pub const fn rules_hash(self, height: u64) -> Hash32 {
        if let Some(activation) = self.time_rolling_activation_height {
            if height >= activation {
                return HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING;
            }
        }
        match self.asert_activation_height {
            Some(activation) if height >= activation => {
                if self.combined_upgrade {
                    HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED
                } else {
                    HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT
                }
            }
            _ => HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC,
        }
    }
}

/// Production selection is source-owned. There is no operator override.
pub fn native_combined_upgrade_activation_height(chain_id: &Hash32) -> Option<u64> {
    if *chain_id == PREMAINNET_CHAIN_ID {
        return PREMAINNET_COMBINED_UPGRADE_ACTIVATION_HEIGHT;
    }
    #[cfg(feature = "combined-upgrade-rehearsal")]
    if *chain_id == COMBINED_REHEARSAL_CHAIN_ID {
        return Some(COMBINED_REHEARSAL_ACTIVATION_HEIGHT);
    }
    None
}

pub fn native_time_rolling_activation_height(chain_id: &Hash32) -> Option<u64> {
    if *chain_id == PREMAINNET_CHAIN_ID {
        return PREMAINNET_TIME_ROLLING_ACTIVATION_HEIGHT;
    }
    #[cfg(feature = "combined-upgrade-rehearsal")]
    if *chain_id == COMBINED_REHEARSAL_CHAIN_ID {
        return Some(TIME_ROLLING_REHEARSAL_ACTIVATION_HEIGHT);
    }
    None
}

pub fn native_time_rolling_active(chain_id: &Hash32, height: u64) -> bool {
    native_time_rolling_activation_height(chain_id).is_some_and(|activation| height >= activation)
}

pub fn native_pow_rules(chain_id: &Hash32) -> PowRulesSchedule {
    if let Some(height) = native_combined_upgrade_activation_height(chain_id) {
        if let Some(time_height) = native_time_rolling_activation_height(chain_id) {
            return PowRulesSchedule::combined_with_time_rolling_at(height, time_height)
                .expect("source-owned time-rolling schedule is valid");
        }
        return PowRulesSchedule::combined_at(height)
            .expect("source-owned combined schedule is valid");
    }
    // Standalone ASERT rehearsal retains its original legacy development seam.
    #[cfg(feature = "asert-rehearsal")]
    if *chain_id == HEGEMON_CHAIN_ID_V1 {
        return PowRulesSchedule::asert_at(20).expect("fixed rehearsal schedule is valid");
    }
    PowRulesSchedule::LEGACY
}

pub fn native_rules_hash(chain_id: &Hash32, height: u64) -> Hash32 {
    native_pow_rules(chain_id).rules_hash(height)
}

pub fn is_asert_rules(rules: &Hash32) -> bool {
    *rules == HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT || is_combined_rules(rules)
}

pub fn is_time_rolling_rules(rules: &Hash32) -> bool {
    *rules == HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_TIME_ROLLING
}

/// Both profiles inherit the original combined version and monetary rules.
pub fn is_combined_rules(rules: &Hash32) -> bool {
    *rules == HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED || is_time_rolling_rules(rules)
}

/// Validate native timestamp carriage and return its exact Bitcoin nTime.
/// Historical profiles retain their full millisecond commitment and truncation.
pub fn bitcoin80_validate_timestamp_for_rules(
    rules: &Hash32,
    timestamp_ms: u64,
) -> Result<u32, LightClientError> {
    let ntime =
        u32::try_from(timestamp_ms / 1_000).map_err(|_| LightClientError::TimestampOutOfRange)?;
    if is_time_rolling_rules(rules) && timestamp_ms % 1_000 != 0 {
        return Err(LightClientError::TimestampNotWholeSecond);
    }
    Ok(ntime)
}

pub fn is_bitcoin80_rules(rules: &Hash32) -> bool {
    *rules == HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
        || *rules == HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT
        || is_combined_rules(rules)
}

/// Generic historical checkpoints can retain their own fixed rules profile.
/// Once either endpoint names a native Bitcoin profile, both endpoints must
/// obey the exact height schedule, including when their rules hashes are equal.
pub(crate) fn validate_rules_pair(
    schedule: PowRulesSchedule,
    parent_height: u64,
    parent_rules: &Hash32,
    child_height: u64,
    child_rules: &Hash32,
) -> Result<(), LightClientError> {
    let valid = if is_bitcoin80_rules(parent_rules) || is_bitcoin80_rules(child_rules) {
        *parent_rules == schedule.rules_hash(parent_height)
            && *child_rules == schedule.rules_hash(child_height)
    } else {
        parent_rules == child_rules
    };
    if valid {
        Ok(())
    } else {
        Err(LightClientError::RulesHashMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitcoin80_work_hash, cumulative_work_after, verify_pow_header_v2,
        verify_pow_header_v2_with_expected_bits,
        verify_pow_header_v2_with_expected_bits_and_schedule, PowHeaderV2, TrustedCheckpointV2,
    };

    fn parent(height: u64, schedule: PowRulesSchedule) -> TrustedCheckpointV2 {
        TrustedCheckpointV2 {
            chain_id: HEGEMON_CHAIN_ID_V1,
            rules_hash: schedule.rules_hash(height),
            height,
            header_hash: [3; 32],
            timestamp_ms: height * ASERT_TARGET_SPACING_MS,
            pow_bits: 0x207fffff,
            cumulative_work: [0; 48],
            header_mmr_root: [4; 32],
            header_mmr_len: height,
        }
    }

    fn child(parent: &TrustedCheckpointV2, schedule: PowRulesSchedule) -> PowHeaderV2 {
        let height = parent.height + 1;
        let mut header = PowHeaderV2 {
            chain_id: parent.chain_id,
            rules_hash: schedule.rules_hash(height),
            height,
            timestamp_ms: parent.timestamp_ms + ASERT_TARGET_SPACING_MS,
            parent_hash: parent.header_hash,
            state_root: [0; 48],
            kernel_root: [0; 48],
            nullifier_root: [0; 48],
            proof_commitment: [0; 48],
            da_root: [0; 48],
            action_root: [0; 32],
            tx_statements_commitment: [0; 48],
            version_commitment: if is_combined_rules(&schedule.rules_hash(height)) {
                crate::bitcoin80_mining_version_payload(crate::BITCOIN80_VERSION)
            } else {
                [0; 48]
            },
            fee_commitment: [0; 48],
            supply_digest: 0,
            tx_count: 0,
            message_root: [0; 48],
            message_count: 0,
            header_mmr_root: [0; 32],
            header_mmr_len: height,
            pow_bits: parent.pow_bits,
            nonce: [0; 32],
            cumulative_work: cumulative_work_after(&parent.cumulative_work, parent.pow_bits)
                .unwrap(),
        };
        for nonce in 0u32..1_000_000 {
            header.nonce[..4].copy_from_slice(&nonce.to_le_bytes());
            if crate::hash_meets_target(&header.pow_hash(), header.pow_bits).unwrap() {
                return header;
            }
        }
        panic!("easy fixture must mine");
    }

    #[test]
    fn combined_rules_hash_and_source_schedule_are_exact() {
        assert_eq!(
            crate::hash32(HEGEMON_LIGHT_CLIENT_RULES_BITCOIN_COMBINED_PREIMAGE),
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED
        );
        assert_ne!(
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED,
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT
        );
        for height in [0, 1, 59, 119, 121, u64::MAX] {
            assert_eq!(
                PowRulesSchedule::combined_at(height),
                Err(LightClientError::InvalidPowRulesSchedule)
            );
        }
        let schedule = PowRulesSchedule::combined_at(120).unwrap();
        assert_eq!(
            schedule.rules_hash(119),
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
        );
        for height in [120, 121, u64::MAX] {
            assert_eq!(
                schedule.rules_hash(height),
                HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED
            );
        }
        assert_eq!(
            native_combined_upgrade_activation_height(&PREMAINNET_CHAIN_ID),
            Some(18_660)
        );
        assert_eq!(native_combined_upgrade_activation_height(&[0x55; 32]), None);
        #[cfg(feature = "combined-upgrade-rehearsal")]
        {
            assert_eq!(
                native_pow_rules(&COMBINED_REHEARSAL_CHAIN_ID),
                PowRulesSchedule::combined_with_time_rolling_at(120, 180).unwrap()
            );
            assert_eq!(
                native_combined_upgrade_activation_height(&COMBINED_REHEARSAL_CHAIN_ID),
                Some(120)
            );
        }
        #[cfg(not(feature = "combined-upgrade-rehearsal"))]
        {
            assert_eq!(
                native_pow_rules(&COMBINED_REHEARSAL_CHAIN_ID),
                PowRulesSchedule::LEGACY
            );
            assert_eq!(
                native_combined_upgrade_activation_height(&COMBINED_REHEARSAL_CHAIN_ID),
                None
            );
        }
    }

    #[test]
    fn asert_rules_hash_matches_exact_profile() {
        assert_eq!(ASERT_TARGET_SPACING_MS, 60_000);
        assert_eq!(ASERT_HALF_LIFE_MS, 3_600_000);
        assert_eq!(
            crate::hash32(HEGEMON_LIGHT_CLIENT_RULES_BITCOIN_ASERT_PREIMAGE),
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT
        );
        assert_ne!(
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT,
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
        );
    }

    #[test]
    fn asert_schedule_keeps_genesis_and_rejects_missing_anchor_heights() {
        assert_eq!(
            PowRulesSchedule::asert_at(0),
            Err(LightClientError::InvalidPowRulesSchedule)
        );
        assert_eq!(
            PowRulesSchedule::asert_at(1),
            Err(LightClientError::InvalidPowRulesSchedule)
        );
        let schedule = PowRulesSchedule::asert_at(20).unwrap();
        for height in [0, 1, 19] {
            assert_eq!(
                schedule.rules_hash(height),
                HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
            );
        }
        for height in [20, 21, u64::MAX] {
            assert_eq!(
                schedule.rules_hash(height),
                HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT
            );
        }
        assert_eq!(
            PowRulesSchedule::LEGACY.rules_hash(u64::MAX),
            HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
        );
    }

    #[test]
    fn asert_rehearsal_preserves_production_and_unknown_schedules() {
        assert_eq!(PREMAINNET_ASERT_ACTIVATION_HEIGHT, Some(18_660));
        assert_eq!(
            native_pow_rules(&PREMAINNET_CHAIN_ID),
            PowRulesSchedule::combined_with_time_rolling_at(
                18_660,
                PREMAINNET_TIME_ROLLING_ACTIVATION_HEIGHT.unwrap()
            )
            .unwrap()
        );
        assert_eq!(native_pow_rules(&[0x55; 32]), PowRulesSchedule::LEGACY);
        #[cfg(feature = "asert-rehearsal")]
        assert_eq!(
            native_pow_rules(&HEGEMON_CHAIN_ID_V1).asert_activation_height(),
            Some(20)
        );
        #[cfg(not(feature = "asert-rehearsal"))]
        assert_eq!(
            native_pow_rules(&HEGEMON_CHAIN_ID_V1),
            PowRulesSchedule::LEGACY
        );
    }

    #[test]
    fn production_combined_activation_requires_exact_boundary_rules() {
        assert_eq!(PREMAINNET_COMBINED_UPGRADE_ACTIVATION_HEIGHT, Some(18_660));
        let schedule = native_pow_rules(&PREMAINNET_CHAIN_ID);
        for (height, expected) in [
            (18_659, HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC),
            (18_660, HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED),
            (18_661, HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED),
        ] {
            assert_eq!(native_rules_hash(&PREMAINNET_CHAIN_ID, height), expected);
            let mut parent = parent(height - 1, schedule);
            parent.chain_id = PREMAINNET_CHAIN_ID;
            let header = child(&parent, schedule);
            assert_eq!(header.rules_hash, expected);
            assert_eq!(
                verify_pow_header_v2_with_expected_bits(&parent, &header, header.pow_bits),
                Ok(header.pow_hash())
            );

            let other_rules = |rules| {
                if rules == HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC {
                    HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_COMBINED
                } else {
                    HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
                }
            };
            let mut bad_parent = parent.clone();
            bad_parent.rules_hash = other_rules(parent.rules_hash);
            assert_eq!(
                verify_pow_header_v2_with_expected_bits(&bad_parent, &header, header.pow_bits),
                Err(LightClientError::RulesHashMismatch)
            );
            let mut bad_header = header.clone();
            bad_header.rules_hash = other_rules(header.rules_hash);
            bad_header.version_commitment = if is_asert_rules(&bad_header.rules_hash) {
                crate::bitcoin80_mining_version_payload(crate::BITCOIN80_VERSION)
            } else {
                [0; 48]
            };
            assert_eq!(
                verify_pow_header_v2_with_expected_bits(&parent, &bad_header, header.pow_bits),
                Err(LightClientError::RulesHashMismatch)
            );
            if height >= 18_660 {
                assert_eq!(
                    verify_pow_header_v2(&parent, &header),
                    Err(LightClientError::UnsupportedDifficultySchedule)
                );
            }
        }
    }

    #[test]
    fn asert_header_transition_requires_both_endpoints_on_schedule() {
        let schedule = PowRulesSchedule::asert_at(20).unwrap();
        for parent_height in [18, 19, 20, 21] {
            let parent = parent(parent_height, schedule);
            let header = child(&parent, schedule);
            assert_eq!(
                verify_pow_header_v2_with_expected_bits_and_schedule(
                    &parent,
                    &header,
                    header.pow_bits,
                    schedule
                ),
                Ok(header.pow_hash())
            );
            assert_eq!(
                header.pow_hash(),
                bitcoin80_work_hash(
                    &header.pre_hash(),
                    &header.parent_hash,
                    header.timestamp_ms,
                    header.pow_bits,
                    header.nonce
                )
                .unwrap()
            );
            assert_eq!(
                verify_pow_header_v2_with_expected_bits_and_schedule(
                    &parent, &header, 0x2070ffff, schedule
                ),
                Err(LightClientError::PowBitsMismatch)
            );
            let wrong = if parent_height < 19 {
                HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT
            } else {
                HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC
            };
            let mut bad_parent = parent.clone();
            let mut bad_header = header.clone();
            bad_parent.rules_hash = wrong;
            bad_header.rules_hash = wrong;
            assert_eq!(
                verify_pow_header_v2_with_expected_bits_and_schedule(
                    &bad_parent,
                    &bad_header,
                    header.pow_bits,
                    schedule
                ),
                Err(LightClientError::RulesHashMismatch)
            );
        }
    }

    #[test]
    fn asert_unscheduled_rules_and_fixed_difficulty_interfaces_fail_closed() {
        let schedule = PowRulesSchedule::asert_at(20).unwrap();
        let parent = parent(19, schedule);
        let mut header = child(&parent, schedule);
        // Unknown chain has no activation, even in the rehearsal build.
        let mut parent = parent;
        parent.chain_id = [0x55; 32];
        header.chain_id = parent.chain_id;
        assert_eq!(
            verify_pow_header_v2_with_expected_bits(&parent, &header, header.pow_bits),
            Err(LightClientError::RulesHashMismatch)
        );
        assert_eq!(
            verify_pow_header_v2(&parent, &header),
            Err(LightClientError::UnsupportedDifficultySchedule)
        );
        let target = crate::bitcoin80_validate_compact(parent.pow_bits).unwrap();
        let work = crate::block_work_from_target(&target);
        assert_eq!(
            crate::verify_long_range_header_shape_v2(&parent, &header, &work, &target),
            Err(LightClientError::UnsupportedDifficultySchedule)
        );
    }
    #[test]
    fn asert_rules_reject_individually_wrong_parent_or_child() {
        let schedule = PowRulesSchedule::asert_at(20).unwrap();
        let parent = parent(19, schedule);
        let header = child(&parent, schedule);
        let mut bad_parent = parent.clone();
        bad_parent.rules_hash = HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASERT;
        assert_eq!(
            verify_pow_header_v2_with_expected_bits_and_schedule(
                &bad_parent,
                &header,
                header.pow_bits,
                schedule
            ),
            Err(LightClientError::RulesHashMismatch)
        );
        let mut bad_header = header.clone();
        bad_header.rules_hash = HEGEMON_LIGHT_CLIENT_RULES_HASH_BITCOIN_ASIC;
        assert_eq!(
            verify_pow_header_v2_with_expected_bits_and_schedule(
                &parent,
                &bad_header,
                header.pow_bits,
                schedule
            ),
            Err(LightClientError::RulesHashMismatch)
        );
    }

    #[test]
    fn asert_headers_keep_bitcoin_timestamp_and_canonical_target_bounds() {
        let schedule = PowRulesSchedule::asert_at(20).unwrap();
        let parent = parent(19, schedule);
        let header = child(&parent, schedule);
        let mut bad = header.clone();
        bad.timestamp_ms = (u64::from(u32::MAX) + 1) * 1_000;
        assert_eq!(
            verify_pow_header_v2_with_expected_bits_and_schedule(
                &parent,
                &bad,
                bad.pow_bits,
                schedule
            ),
            Err(LightClientError::TimestampOutOfRange)
        );
        for bits in [0x2080_0000, 0x2100_8000, 0] {
            let mut bad = header.clone();
            bad.pow_bits = bits;
            assert_eq!(
                verify_pow_header_v2_with_expected_bits_and_schedule(&parent, &bad, bits, schedule),
                Err(LightClientError::InvalidCompactTarget)
            );
        }
    }
}
