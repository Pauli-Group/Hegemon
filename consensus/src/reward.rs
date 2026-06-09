use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::types::{CoinbaseData, SupplyDigest};

// =============================================================================
// CHAIN PARAMETERS - SINGLE SOURCE OF TRUTH
// All other crates should import from here or from runtime re-exports.
// See TOKENOMICS_CALCULATION.md for the derivation of these parameters.
// =============================================================================

pub const COIN: u64 = 100_000_000;

/// Seconds in a year (365 × 24 × 3,600)
pub const T_YEAR: u64 = 31_536_000;

/// Target block time in seconds (60 seconds / 1 minute)
pub const T_BLOCK_SECONDS: u64 = 60;

/// Duration of one issuance epoch in years
pub const Y_EPOCH: u64 = 4;

/// Epoch duration in seconds (Y_EPOCH × T_YEAR)
pub const T_EPOCH_SECONDS: u64 = Y_EPOCH * T_YEAR;

/// Blocks per epoch (4 years of 60s blocks = 2,102,400 blocks)
pub const BLOCKS_PER_EPOCH: u64 = T_EPOCH_SECONDS / T_BLOCK_SECONDS;

/// Maximum supply: 21 million coins
pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;

/// Initial block reward R0 = (S_MAX × t_block) / (2 × Y_EPOCH × T_YEAR)
/// For 60s blocks: R0 = (21,000,000 × 60) / (2 × 4 × 31,536,000) ≈ 4.98 HEG
/// In base units: ~498,287,671 (~4.98 coins)
pub const INITIAL_SUBSIDY: u64 =
    (MAX_SUPPLY as u128 * T_BLOCK_SECONDS as u128 / (2 * Y_EPOCH as u128 * T_YEAR as u128)) as u64;

/// Halving interval derived from BLOCKS_PER_EPOCH
pub const HALVING_INTERVAL: u64 = BLOCKS_PER_EPOCH;

/// Target block time in milliseconds (60 seconds / 1 minute).
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 60_000;

/// Number of blocks between difficulty adjustments.
/// At 60s blocks, 10 blocks = 10 minutes between adjustments.
pub const RETARGET_WINDOW: u64 = 10;

/// Expected total time for RETARGET_WINDOW blocks (10 * 60s = 600s = 10 minutes).
pub const RETARGET_TIMESPAN_MS: u64 = RETARGET_WINDOW * TARGET_BLOCK_INTERVAL_MS;

/// Maximum adjustment factor per retarget (4x up or down).
pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;

/// Genesis difficulty: ~100 kH/s * 60 seconds = 6,000,000 expected hashes per block.
pub const GENESIS_DIFFICULTY: u128 = 6_000_000;

/// Genesis compact bits: 0x1e218def encodes target = MAX_U256 / 500,000.
pub const GENESIS_BITS: u32 = 0x1e21_8def;

/// Minimum difficulty to prevent divide-by-zero.
pub const MIN_DIFFICULTY: u128 = 1;

pub const MEDIAN_TIME_WINDOW: usize = 11;

/// Maximum timestamp drift allowed (90 seconds for 60s blocks).
pub const MAX_FUTURE_SKEW_MS: u64 = 90_000;

pub fn block_subsidy(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let halvings = (height - 1) / HALVING_INTERVAL;
    let shift = halvings.min(63);
    INITIAL_SUBSIDY >> shift
}

pub fn adjusted_timespan(actual_ms: u64) -> u64 {
    let min = RETARGET_TIMESPAN_MS / 4;
    let max = RETARGET_TIMESPAN_MS * 4;
    actual_ms.clamp(min, max)
}

pub fn retarget_target(prev_target: &BigUint, actual_timespan_ms: u64) -> BigUint {
    if prev_target.is_zero() {
        return BigUint::zero();
    }
    let actual = BigUint::from(adjusted_timespan(actual_timespan_ms));
    let expected = BigUint::from(RETARGET_TIMESPAN_MS);
    let mut target = prev_target * actual;
    if target.is_zero() {
        return target;
    }
    target /= expected;
    if target.is_zero() {
        BigUint::one()
    } else {
        target
    }
}

pub fn update_supply_digest(parent: SupplyDigest, delta: i128) -> Option<SupplyDigest> {
    if delta >= 0 {
        parent.checked_add(delta as u128)
    } else {
        let magnitude = (-delta) as u128;
        parent.checked_sub(magnitude)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyChainStep {
    pub minted: u64,
    pub fees: i64,
    pub burns: u64,
    pub claimed_supply: SupplyDigest,
}

impl SupplyChainStep {
    pub fn coinbase(&self) -> CoinbaseData {
        CoinbaseData {
            minted: self.minted,
            fees: self.fees,
            burns: self.burns,
            source: crate::types::CoinbaseSource::BalanceTag([0u8; 48]),
        }
    }
}

pub fn validate_supply_transition(
    parent: SupplyDigest,
    coinbase: &CoinbaseData,
    claimed_supply: SupplyDigest,
) -> Option<SupplyDigest> {
    let expected = expected_supply_after_transition(parent, coinbase)?;
    if expected == claimed_supply {
        Some(expected)
    } else {
        None
    }
}

pub fn expected_supply_after_transition(
    parent: SupplyDigest,
    coinbase: &CoinbaseData,
) -> Option<SupplyDigest> {
    update_supply_digest(parent, coinbase.net_native_delta())
}

pub fn validate_supply_chain(
    genesis_supply: SupplyDigest,
    steps: &[SupplyChainStep],
) -> Option<SupplyDigest> {
    let mut supply = genesis_supply;
    for step in steps {
        supply = validate_supply_transition(supply, &step.coinbase(), step.claimed_supply)?;
    }
    Some(supply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::CoinbaseSource;
    use serde::Deserialize;
    use std::collections::BTreeSet;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSupplyVectorFile {
        schema_version: u32,
        monetary_constants: LeanMonetaryConstants,
        subsidy_schedule_cases: Vec<LeanSubsidyScheduleCase>,
        consensus_supply_cases: Vec<LeanConsensusSupplyCase>,
        native_supply_cases: Vec<serde_json::Value>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSupplyInvariantVectorFile {
        schema_version: u32,
        supply_chain_cases: Vec<LeanSupplyChainCase>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanMonetaryConstants {
        coin: u64,
        target_block_seconds: u64,
        year_seconds: u64,
        epoch_years: u64,
        halving_interval: u64,
        max_monetary_supply: String,
        initial_subsidy: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSubsidyScheduleCase {
        name: String,
        height: u64,
        expected_halving_epoch: u64,
        expected_subsidy: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanConsensusSupplyCase {
        name: String,
        parent_supply: String,
        minted: u64,
        fees: String,
        burns: u64,
        expected_net_delta: String,
        expected_supply: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSupplyChainCase {
        name: String,
        genesis_supply: String,
        steps: Vec<LeanSupplyChainStep>,
        expected_final_supply: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSupplyChainStep {
        minted: u64,
        fees: String,
        burns: u64,
        claimed_supply: String,
    }

    #[test]
    fn halving_schedule_matches_expectations() {
        assert_eq!(block_subsidy(0), 0);
        assert_eq!(block_subsidy(1), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(HALVING_INTERVAL), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(HALVING_INTERVAL + 1), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn timespan_is_clamped() {
        assert_eq!(adjusted_timespan(0), RETARGET_TIMESPAN_MS / 4);
        assert_eq!(
            adjusted_timespan(RETARGET_TIMESPAN_MS * 10),
            RETARGET_TIMESPAN_MS * 4
        );
    }

    #[test]
    fn supply_digest_handles_signed_delta() {
        let parent: SupplyDigest = 100;
        assert_eq!(update_supply_digest(parent, 25), Some(125));
        assert_eq!(update_supply_digest(parent, -50), Some(50));
        assert_eq!(update_supply_digest(parent, -150), None);
    }

    #[test]
    fn total_minted_is_bounded_by_max_supply() {
        let mut subsidy = INITIAL_SUBSIDY as u128;
        let mut total: u128 = 0;

        while subsidy > 0 {
            total += subsidy * HALVING_INTERVAL as u128;
            subsidy >>= 1;
        }

        assert!(total <= MAX_SUPPLY as u128);
        assert!(total >= (MAX_SUPPLY as u128) - (COIN as u128));
    }

    #[test]
    fn lean_generated_supply_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_SUPPLY_VECTORS") else {
            eprintln!("HEGEMON_LEAN_SUPPLY_VECTORS not set; skipping generated Lean vector check");
            return;
        };
        let raw = std::fs::read_to_string(&path).expect("read generated Lean supply vectors");
        let vectors: LeanSupplyVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean supply vectors");
        assert_eq!(vectors.schema_version, 1);
        verify_lean_monetary_constants(&vectors.monetary_constants);
        assert!(
            !vectors.subsidy_schedule_cases.is_empty(),
            "Lean subsidy schedule cases must not be empty"
        );
        assert!(
            !vectors.consensus_supply_cases.is_empty(),
            "Lean consensus supply cases must not be empty"
        );
        assert!(
            !vectors.native_supply_cases.is_empty(),
            "Lean native supply cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.subsidy_schedule_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_subsidy_schedule_case(case);
        }
        for case in &vectors.consensus_supply_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_consensus_supply_case(case);
        }
    }

    #[test]
    fn lean_generated_supply_invariant_vectors_match_production() {
        let Ok(path) = std::env::var("HEGEMON_LEAN_SUPPLY_INVARIANT_VECTORS") else {
            eprintln!(
                "HEGEMON_LEAN_SUPPLY_INVARIANT_VECTORS not set; skipping generated Lean vector check"
            );
            return;
        };
        let raw =
            std::fs::read_to_string(&path).expect("read generated Lean supply invariant vectors");
        let vectors: LeanSupplyInvariantVectorFile =
            serde_json::from_str(&raw).expect("parse generated Lean supply invariant vectors");
        assert_eq!(vectors.schema_version, 1);
        assert!(
            !vectors.supply_chain_cases.is_empty(),
            "Lean supply-chain cases must not be empty"
        );

        let mut names = BTreeSet::new();
        for case in &vectors.supply_chain_cases {
            assert!(names.insert(case.name.clone()));
            verify_lean_supply_chain_case(case);
        }
    }

    fn verify_lean_supply_chain_case(case: &LeanSupplyChainCase) {
        let genesis_supply = parse_u128(&case.genesis_supply);
        let steps = case
            .steps
            .iter()
            .map(|step| SupplyChainStep {
                minted: step.minted,
                fees: parse_i64(&step.fees),
                burns: step.burns,
                claimed_supply: parse_u128(&step.claimed_supply),
            })
            .collect::<Vec<_>>();
        let expected_final_supply = case.expected_final_supply.as_deref().map(parse_u128);

        assert_eq!(
            validate_supply_chain(genesis_supply, &steps),
            expected_final_supply,
            "{} production supply-chain replay drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_monetary_constants(constants: &LeanMonetaryConstants) {
        assert_eq!(constants.coin, COIN, "COIN drifted from Lean spec");
        assert_eq!(
            constants.target_block_seconds, T_BLOCK_SECONDS,
            "T_BLOCK_SECONDS drifted from Lean spec"
        );
        assert_eq!(
            constants.year_seconds, T_YEAR,
            "T_YEAR drifted from Lean spec"
        );
        assert_eq!(
            constants.epoch_years, Y_EPOCH,
            "Y_EPOCH drifted from Lean spec"
        );
        assert_eq!(
            constants.halving_interval, HALVING_INTERVAL,
            "HALVING_INTERVAL drifted from Lean spec"
        );
        assert_eq!(
            parse_u64(&constants.max_monetary_supply),
            MAX_SUPPLY,
            "MAX_SUPPLY drifted from Lean spec"
        );
        assert_eq!(
            constants.initial_subsidy, INITIAL_SUBSIDY,
            "INITIAL_SUBSIDY drifted from Lean spec"
        );
    }

    fn verify_lean_subsidy_schedule_case(case: &LeanSubsidyScheduleCase) {
        let actual_epoch = if case.height == 0 {
            0
        } else {
            ((case.height - 1) / HALVING_INTERVAL).min(63)
        };
        assert_eq!(
            actual_epoch, case.expected_halving_epoch,
            "{} production halving epoch drifted from Lean spec",
            case.name
        );
        assert_eq!(
            block_subsidy(case.height),
            case.expected_subsidy,
            "{} production subsidy schedule drifted from Lean spec",
            case.name
        );
    }

    fn verify_lean_consensus_supply_case(case: &LeanConsensusSupplyCase) {
        let parent_supply = parse_u128(&case.parent_supply);
        let fees = parse_i64(&case.fees);
        let expected_net_delta = parse_i128(&case.expected_net_delta);
        let expected_supply = case.expected_supply.as_deref().map(parse_u128);
        let coinbase = CoinbaseData {
            minted: case.minted,
            fees,
            burns: case.burns,
            source: CoinbaseSource::BalanceTag([0u8; 48]),
        };

        assert_eq!(
            coinbase.net_native_delta(),
            expected_net_delta,
            "{} production coinbase native delta drifted from Lean spec",
            case.name
        );
        assert_eq!(
            update_supply_digest(parent_supply, coinbase.net_native_delta()),
            expected_supply,
            "{} production supply digest update drifted from Lean spec",
            case.name
        );
    }

    fn parse_u128(raw: &str) -> u128 {
        raw.parse::<u128>()
            .expect("Lean supply value must be a decimal u128")
    }

    fn parse_i128(raw: &str) -> i128 {
        raw.parse::<i128>()
            .expect("Lean delta value must be a decimal i128")
    }

    fn parse_u64(raw: &str) -> u64 {
        raw.parse::<u64>()
            .expect("Lean monetary value must be a decimal u64")
    }

    fn parse_i64(raw: &str) -> i64 {
        raw.parse::<i64>()
            .expect("Lean fee value must be a decimal i64")
    }
}
