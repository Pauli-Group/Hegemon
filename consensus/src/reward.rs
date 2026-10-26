use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::types::{CoinbaseData, SupplyDigest};

// =============================================================================
// CHAIN PARAMETERS - SINGLE SOURCE OF TRUTH
// All other crates should import from here or from runtime re-exports.
// See TOKENOMICS_CALCULATION.md for the derivation of these parameters.
// =============================================================================

pub const COIN: u64 = 100_000_000;

pub use protocol_versioning::{
    coinbase_mature_in_block, coinbase_maturity_height, coinbase_release_height,
    COINBASE_MATURITY, COINBASE_MATURITY_RULES_ID,
};

/// Seconds in a year (365 × 24 × 3,600)
pub const T_YEAR: u64 = 31_536_000;

/// Target block time in seconds (60 seconds / 1 minute)
pub const T_BLOCK_SECONDS: u64 = 60;

/// Legacy calendar label retained for compatibility, not the issuance interval.
/// An issuance epoch is BLOCKS_PER_EPOCH blocks, not four exact calendar years.
pub const Y_EPOCH: u64 = 4;

/// Blocks per issuance epoch, independently of calendar-year conventions.
pub const BLOCKS_PER_EPOCH: u64 = 2_100_000;

/// Target elapsed seconds per issuance epoch (2,100,000 × 60).
pub const T_EPOCH_SECONDS: u64 = BLOCKS_PER_EPOCH * T_BLOCK_SECONDS;

/// Maximum supply: 21 million coins
pub const MAX_SUPPLY: u64 = 21_000_000 * COIN;

/// Initial block subsidy: exactly five coins.
pub const INITIAL_SUBSIDY: u64 = 5 * COIN;

/// Halving interval derived from BLOCKS_PER_EPOCH
pub const HALVING_INTERVAL: u64 = BLOCKS_PER_EPOCH;

/// Consensus identity of the exact 21M-coin epoch-budget schedule.
/// Any issuance-policy change requires a new identity and fresh genesis.
pub const EMISSION_SCHEDULE_ID: &[u8] =
    b"hegemon-native-emission-21m-atoms1e8-5hgn-epoch2100000-prefix-v1";

/// Target block time in milliseconds (60 seconds / 1 minute).
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 60_000;

/// Number of blocks between difficulty adjustments.
/// At 60s blocks, 10 blocks = 10 minutes between adjustments.
pub const RETARGET_WINDOW: u64 = 10;

/// Expected total time for RETARGET_WINDOW blocks (10 * 60s = 600s = 10 minutes).
pub const RETARGET_TIMESPAN_MS: u64 = RETARGET_WINDOW * TARGET_BLOCK_INTERVAL_MS;

/// Maximum adjustment factor per retarget (4x up or down).
pub const MAX_ADJUSTMENT_FACTOR: u64 = 4;

/// Bootstrap CPU-devnet launch difficulty: 1,000,000 expected hashes per block.
///
/// The protocol target remains 60 seconds via retargeting. The launch target is
/// deliberately conservative so a fresh two-node devnet proves liveness before
/// the retarget schedule tightens difficulty.
pub const GENESIS_DIFFICULTY: u128 = 1_000_000;

/// Genesis compact bits: 0x1e10c6f7 encodes target ~= MAX_U256 / 1,000,000.
pub const GENESIS_BITS: u32 = 0x1e10_c6f7;

/// Minimum difficulty to prevent divide-by-zero.
pub const MIN_DIFFICULTY: u128 = 1;

pub const MEDIAN_TIME_WINDOW: usize = 11;

/// Maximum timestamp drift allowed (90 seconds for 60s blocks).
pub const MAX_FUTURE_SKEW_MS: u64 = 90_000;

pub fn block_subsidy(height: u64) -> u64 {
    if height == 0 {
        return 0;
    }
    let epoch = (height - 1) / HALVING_INTERVAL;
    let slot = (height - 1) % HALVING_INTERVAL;
    let budget = epoch_subsidy_budget(epoch) as u128;
    let interval = HALVING_INTERVAL as u128;
    let before = slot as u128 * budget / interval;
    let after = (slot as u128 + 1) * budget / interval;
    (after - before) as u64
}

/// Scheduled issuance still unallocated at the start of an epoch.
/// Epochs beyond the u64 shift range have no remaining budget.
pub fn remaining_subsidy_budget(epoch: u64) -> u64 {
    if epoch >= u64::BITS as u64 {
        0
    } else {
        MAX_SUPPLY >> epoch as u32
    }
}

/// Exact atoms scheduled across all blocks of an epoch.
pub fn epoch_subsidy_budget(epoch: u64) -> u64 {
    if epoch >= u64::BITS as u64 {
        return 0;
    }
    remaining_subsidy_budget(epoch) - remaining_subsidy_budget(epoch + 1)
}

/// Cumulative subsidy scheduled through height, including that block.
/// This is the schedule ceiling; omitted coinbases do not mint these atoms.
pub fn scheduled_subsidy(height: u64) -> u64 {
    let epoch = height / HALVING_INTERVAL;
    let slots = height % HALVING_INTERVAL;
    let allocated = MAX_SUPPLY - remaining_subsidy_budget(epoch);
    let partial =
        slots as u128 * epoch_subsidy_budget(epoch) as u128 / HALVING_INTERVAL as u128;
    allocated + partial as u64
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
        emission_model: String,
        monetary_constants: LeanMonetaryConstants,
        subsidy_schedule_cases: Vec<LeanSubsidyScheduleCase>,
        epoch_budget_cases: Vec<LeanEpochBudgetCase>,
        slot_subsidy_cases: Vec<LeanSlotSubsidyCase>,
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
        epoch_seconds: u64,
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
        expected_epoch_budget: u64,
        expected_scheduled_subsidy: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanEpochBudgetCase {
        name: String,
        epoch: u64,
        expected_remaining_budget: u64,
        expected_epoch_budget: u64,
    }

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LeanSlotSubsidyCase {
        name: String,
        epoch: u64,
        slot: u64,
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
        assert_eq!(MAX_SUPPLY, 2_100_000_000_000_000);
        assert_eq!(HALVING_INTERVAL, 2_100_000);
        assert_eq!(T_EPOCH_SECONDS, 126_000_000);
        assert_eq!(block_subsidy(0), 0);
        assert_eq!(block_subsidy(1), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(HALVING_INTERVAL), INITIAL_SUBSIDY);
        assert_eq!(block_subsidy(HALVING_INTERVAL + 1), INITIAL_SUBSIDY / 2);
    }

    #[test]
    fn fractional_epoch_atoms_are_distributed_and_not_discarded() {
        let first = 9 * HALVING_INTERVAL + 1;
        assert_eq!(block_subsidy(first), 976_562);
        assert_eq!(block_subsidy(first + 1), 976_563);
        assert_eq!(block_subsidy(first + 2), 976_562);
        assert_eq!(block_subsidy(10 * HALVING_INTERVAL), 976_563);
        let total: u64 = (first..=10 * HALVING_INTERVAL).map(block_subsidy).sum();
        assert_eq!(total, epoch_subsidy_budget(9));
    }

    #[test]
    fn scheduled_prefix_matches_block_increments_and_epoch_budgets() {
        assert_eq!(scheduled_subsidy(0), 0);
        for epoch in 0..64 {
            let start = epoch * HALVING_INTERVAL;
            let end = start + HALVING_INTERVAL;
            assert_eq!(
                scheduled_subsidy(end) - scheduled_subsidy(start),
                epoch_subsidy_budget(epoch)
            );
            for slot in [
                0,
                1,
                HALVING_INTERVAL / 2,
                HALVING_INTERVAL - 2,
                HALVING_INTERVAL - 1,
            ] {
                let height = start + slot + 1;
                assert_eq!(
                    scheduled_subsidy(height) - scheduled_subsidy(height - 1),
                    block_subsidy(height)
                );
            }
        }
    }

    #[test]
    fn final_atom_and_unbounded_height_extinction_are_exact() {
        let first_zero = 29 * HALVING_INTERVAL + 1;
        assert_eq!(first_zero, 60_900_001);
        assert_eq!(block_subsidy(first_zero), 0);
        assert_eq!(block_subsidy(first_zero + 1), 1);
        assert_eq!(block_subsidy(30 * HALVING_INTERVAL), 1);
        let last = 51 * HALVING_INTERVAL;
        assert_eq!(last, 107_100_000);
        assert_eq!(block_subsidy(last - 1), 0);
        assert_eq!(block_subsidy(last), 1);
        assert_eq!(scheduled_subsidy(last - 1), MAX_SUPPLY - 1);
        assert_eq!(scheduled_subsidy(last), MAX_SUPPLY);
        assert_eq!(block_subsidy(last + 1), 0);
        assert_eq!(block_subsidy(u64::MAX), 0);
        assert_eq!(scheduled_subsidy(u64::MAX), MAX_SUPPLY);
        assert_eq!(remaining_subsidy_budget(64), 0);
        assert_eq!(remaining_subsidy_budget(63), 0);
        assert_eq!(epoch_subsidy_budget(63), 0);
        assert_eq!(epoch_subsidy_budget(64), 0);
        assert_eq!(remaining_subsidy_budget(u64::MAX), 0);
        assert_eq!(epoch_subsidy_budget(u64::MAX), 0);
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
    fn total_scheduled_is_exactly_max_supply() {
        let total: u64 = (0..64).map(epoch_subsidy_budget).sum();
        assert_eq!(total, MAX_SUPPLY);
        assert_eq!(scheduled_subsidy(64 * HALVING_INTERVAL), MAX_SUPPLY);
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
        assert_eq!(vectors.schema_version, 2);
        assert_eq!(vectors.emission_model, "epoch-budget-prefix-differences-v1");
        verify_lean_monetary_constants(&vectors.monetary_constants);
        assert!(
            !vectors.subsidy_schedule_cases.is_empty(),
            "Lean subsidy schedule cases must not be empty"
        );
        assert!(
            !vectors.epoch_budget_cases.is_empty(),
            "Lean epoch budget cases must not be empty"
        );
        assert!(
            !vectors.slot_subsidy_cases.is_empty(),
            "Lean slot subsidy cases must not be empty"
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
        for case in &vectors.epoch_budget_cases {
            assert!(names.insert(case.name.clone()));
            assert_eq!(
                remaining_subsidy_budget(case.epoch),
                case.expected_remaining_budget,
                "{} remaining budget",
                case.name
            );
            assert_eq!(
                epoch_subsidy_budget(case.epoch),
                case.expected_epoch_budget,
                "{} epoch budget",
                case.name
            );
        }
        for case in &vectors.slot_subsidy_cases {
            assert!(names.insert(case.name.clone()));
            assert!(
                case.slot < HALVING_INTERVAL,
                "{} slot is outside epoch",
                case.name
            );
            let height = case
                .epoch
                .checked_mul(HALVING_INTERVAL)
                .and_then(|start| start.checked_add(case.slot))
                .and_then(|before| before.checked_add(1))
                .expect("Lean slot vector must name a u64 block height");
            assert_eq!(
                block_subsidy(height),
                case.expected_subsidy,
                "{} slot subsidy",
                case.name
            );
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
            constants.epoch_seconds, T_EPOCH_SECONDS,
            "T_EPOCH_SECONDS drifted from Lean spec"
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
            (case.height - 1) / HALVING_INTERVAL
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
        assert_eq!(
            epoch_subsidy_budget(actual_epoch),
            case.expected_epoch_budget,
            "{} production epoch budget drifted from Lean spec",
            case.name
        );
        assert_eq!(
            scheduled_subsidy(case.height),
            case.expected_scheduled_subsidy,
            "{} production cumulative schedule drifted from Lean spec",
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
