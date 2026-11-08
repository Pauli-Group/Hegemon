//! Deterministic finite ASERT experiments; run with:
//! cargo run --release -p consensus-light-client --example asert_scenarios
//!
//! Consensus targets come from the actual exported integer ASERT implementation.
//! Floating point is used only for simulated exponential block arrivals and
//! statistics; it never supplies an alternative consensus difficulty formula.

use consensus_light_client::{asert_next_bits, bitcoin80_validate_compact, AsertAnchor};
use std::collections::VecDeque;

const SPACING_MS: u64 = 60_000;
const REFERENCE_BITS: u32 = 0x1d00_ffff;
const SEED: u64 = 0x4847_4e41_5345_5254;
const NORMAL_RUNS: usize = 32;
const EXTREME_RUNS: usize = 8;
const MAX_BLOCKS: usize = 4_096;
const HOUR: f64 = 3_600.0;
const DAY: f64 = 86_400.0;

#[derive(Clone)]
struct Scenario {
    name: &'static str,
    horizon: f64,
    rates: Vec<(f64, f64)>,
    recovery_from: Option<f64>,
    runs: usize,
    compare_switching: bool,
}

impl Scenario {
    fn rate_and_next_change(&self, time: f64) -> (f64, f64) {
        let index = self.rates.partition_point(|(start, _)| *start <= time) - 1;
        let next = self
            .rates
            .get(index + 1)
            .map_or(self.horizon, |(start, _)| *start);
        (self.rates[index].1, next.min(self.horizon))
    }

    /// Hash-seconds measured in units of the initial reference hash rate.
    fn extra_hash_seconds(&self, start: f64, stop: f64) -> f64 {
        let mut time = start;
        let mut total = 0.0;
        while time < stop {
            let (rate, change) = self.rate_and_next_change(time);
            let end = change.min(stop);
            total += (rate - 1.0).max(0.0) * (end - time);
            time = end;
        }
        total
    }
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn exponential(&mut self) -> f64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        let uniform = ((z >> 11) as f64 + 0.5) / ((1u64 << 53) as f64);
        -uniform.ln()
    }
}

fn target_value(bits: u32) -> f64 {
    bitcoin80_validate_compact(bits)
        .expect("ASERT returned a valid canonical target")
        .into_iter()
        .fold(0.0, |value, byte| value * 256.0 + f64::from(byte))
        + 1.0
}

/// Integrate the remaining exponential hazard across each wall-clock hash-rate
/// change. The target stays fixed while searching for a block, including a stall.
fn next_arrival(
    start: f64,
    target_ratio: f64,
    scenario: &Scenario,
    rng: &mut SplitMix64,
) -> Option<f64> {
    let mut time = start;
    let mut hazard = rng.exponential();
    while time < scenario.horizon {
        let (hash_rate, change) = scenario.rate_and_next_change(time);
        let blocks_per_second = hash_rate * target_ratio / 60.0;
        let available = blocks_per_second * (change - time);
        if hazard < available {
            let arrival = time + hazard / blocks_per_second;
            // Existing admission requires a strictly advancing millisecond
            // timestamp. No propagation, orphan, or networking delay is modeled.
            let admissible = ((arrival * 1_000.0).ceil() / 1_000.0).max(start + 0.001);
            return (admissible < scenario.horizon).then_some(admissible);
        }
        hazard -= available;
        time = change;
    }
    None
}

struct Run {
    intervals: Vec<f64>,
    first_post_drop: Option<f64>,
    recovery: Option<f64>,
    max_blocks_per_minute: usize,
    budget_censored: bool,
    elapsed: f64,
    steady_expected_rewards: f64,
    switching_expected_rewards: f64,
    switching_hash_seconds: f64,
}

fn simulate(scenario: &Scenario, half_life_ms: u64, seed: u64) -> Run {
    let anchor = AsertAnchor {
        height: 1,
        parent_timestamp_ms: 0,
        pow_bits: REFERENCE_BITS,
    };
    // The anchor was mined exactly on schedule at 60 seconds. All scenario
    // times are relative to that anchor, so the first ASERT target is unchanged.
    let mut parent_height = 1u64;
    let mut parent_timestamp_ms = SPACING_MS;
    let mut time = 0.0;
    let reference = target_value(REFERENCE_BITS);
    let mut rng = SplitMix64(seed);
    let mut recent = VecDeque::new();
    let mut result = Run {
        intervals: Vec::new(),
        first_post_drop: None,
        recovery: None,
        max_blocks_per_minute: 0,
        budget_censored: false,
        elapsed: 0.0,
        steady_expected_rewards: 0.0,
        switching_expected_rewards: 0.0,
        switching_hash_seconds: 0.0,
    };
    loop {
        let bits = asert_next_bits(
            anchor,
            parent_height,
            parent_timestamp_ms,
            SPACING_MS,
            half_life_ms,
        )
        .expect("valid bounded experiment parameters");
        let target_ratio = target_value(bits) / reference;
        if let Some(drop_time) = scenario.recovery_from {
            if time >= drop_time && result.recovery.is_none() {
                let rate = scenario.rate_and_next_change(time).0;
                let expected_interval = 60.0 / (rate * target_ratio);
                if (30.0..=120.0).contains(&expected_interval) {
                    result.recovery = Some(time - drop_time);
                }
            }
        }
        if result.intervals.len() == MAX_BLOCKS {
            result.budget_censored = true;
            result.elapsed = time;
            break;
        }
        let Some(arrival) = next_arrival(time, target_ratio, scenario, &mut rng) else {
            result.switching_hash_seconds += scenario.extra_hash_seconds(time, scenario.horizon);
            result.elapsed = scenario.horizon;
            break;
        };
        result.switching_hash_seconds += scenario.extra_hash_seconds(time, arrival);
        result.intervals.push(arrival - time);
        if let Some(drop_time) = scenario.recovery_from {
            if arrival >= drop_time && result.first_post_drop.is_none() {
                result.first_post_drop = Some(arrival - drop_time);
            }
        }
        if scenario.compare_switching {
            // Expected reward allocation conditional on this block arriving.
            // A constant unit baseline miner remains present; extra miners add
            // nine units during each high phase. No strategic policy is optimized.
            let rate = scenario.rate_and_next_change(arrival).0;
            result.steady_expected_rewards += 1.0 / rate;
            result.switching_expected_rewards += (rate - 1.0) / rate;
        }
        recent.push_back(arrival);
        while recent.front().is_some_and(|first| arrival - first >= 60.0) {
            recent.pop_front();
        }
        result.max_blocks_per_minute = result.max_blocks_per_minute.max(recent.len());
        time = arrival;
        parent_height += 1;
        parent_timestamp_ms = SPACING_MS + (time * 1_000.0).round() as u64;
    }
    result
}

/// Nearest-rank empirical quantile; no interpolation or fitted distribution.
fn quantile(values: &mut [f64], percentile: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    let index = ((percentile * values.len() as f64).ceil() as usize).saturating_sub(1);
    values[index.min(values.len() - 1)]
}

fn duration(seconds: f64) -> String {
    if seconds >= DAY {
        format!("{:.2} d", seconds / DAY)
    } else if seconds >= HOUR {
        format!("{:.2} h", seconds / HOUR)
    } else if seconds >= 60.0 {
        format!("{:.2} min", seconds / 60.0)
    } else {
        format!("{seconds:.3} s")
    }
}

fn optional_quantiles(values: &[Option<f64>]) -> String {
    let mut observed: Vec<_> = values.iter().filter_map(|value| *value).collect();
    if observed.is_empty() {
        return format!("none; {}/{} censored", values.len(), values.len());
    }
    let median = quantile(&mut observed, 0.5);
    let p95 = quantile(&mut observed, 0.95);
    format!(
        "{} / {}; {}/{} censored",
        duration(median),
        duration(p95),
        values.len() - observed.len(),
        values.len()
    )
}

fn scenarios() -> Vec<Scenario> {
    let mut switching_rates = vec![(0.0, 1.0)];
    for phase in 0..18 {
        switching_rates.push((
            3.0 * HOUR + f64::from(phase) * 0.5 * HOUR,
            if phase % 2 == 0 { 10.0 } else { 1.0 },
        ));
    }
    vec![
        Scenario {
            name: "steady 1x",
            horizon: 12.0 * HOUR,
            rates: vec![(0.0, 1.0)],
            recovery_from: None,
            runs: NORMAL_RUNS,
            compare_switching: false,
        },
        Scenario {
            name: "10x arrival then departure",
            horizon: 12.0 * HOUR,
            rates: vec![(0.0, 1.0), (3.0 * HOUR, 10.0), (6.0 * HOUR, 1.0)],
            recovery_from: Some(6.0 * HOUR),
            runs: NORMAL_RUNS,
            compare_switching: true,
        },
        Scenario {
            name: "repeated 10x switching",
            horizon: 12.0 * HOUR,
            rates: switching_rates,
            recovery_from: None,
            runs: NORMAL_RUNS,
            compare_switching: true,
        },
        Scenario {
            name: "10000x departure at fixed parent",
            horizon: 45.0 * DAY,
            rates: vec![(0.0, 0.0001)],
            recovery_from: Some(0.0),
            runs: EXTREME_RUNS,
            compare_switching: false,
        },
    ]
}

fn main() {
    println!("# Bounded ASERT scenarios\n");
    println!("Run: `cargo run --release -p consensus-light-client --example asert_scenarios`\n");
    println!("Actual integer ASERT API; 60-second spacing; fixed anchor height 1, anchor-parent time 0, anchor time 60000 ms, reference bits 0x{REFERENCE_BITS:08x}. Hegemon's existing target limit remains 0x207fffff. Half-lives: 30 minutes, 1 hour, 3 hours.\n");
    println!("SplitMix64 base seed 0x{SEED:016x}; run i uses base XOR ((i+1)*0x9e3779b97f4a7c15) with wrapping multiplication. Each half-life receives the same seed set. Exponential hazard is integrated across wall-clock hashrate changes; timestamps round up to milliseconds and advance at least 1 ms.\n");
    println!("Normal scenarios: {NORMAL_RUNS} runs each, 12 hours. Arrival/departure: 1x until hour 3, 10x until hour 6, then persistent 1x. Switching: after hour 3, alternate 10x and 1x every 30 minutes. Extreme departure: {EXTREME_RUNS} runs from the identical fixed parent, persistent 0.0001x hash rate, up to 45 days. Every run stops at {MAX_BLOCKS} blocks; capped runs are reported.\n");
    println!("Interval statistics pool all observed intervals, including initial and transition intervals. They omit the unfinished final waiting interval and are therefore conditional on observed blocks. Quantiles use nearest rank. Maximum burst counts blocks within a sliding 60-second interval. Recovery means the first post-drop target with conditional expected interval in [30,120] seconds; it does not establish sustained steady production. Censored means no such observation before the horizon or block cap. Recovery quantiles use only uncensored runs; with substantial censoring they are not estimates of the full recovery distribution.\n");
    println!("Switch/steady reward per hash compares a unit baseline miner present throughout with nine extra units present only in high phases. Rewards are expected proportional allocations conditional on observed blocks; exposure is integrated in hash-seconds. Reward value is constant, fees absent, and no switching strategy is optimized.\n");
    println!("This finite idealized experiment omits network latency, orphaning, transaction processing, price feedback and strategic timestamp manipulation. In particular, catch-up burst counts are controller behavior under those assumptions, not achievable node throughput or a security proof.\n");
    println!("| Scenario | Half-life | Blocks | Interval median / p95 / max | Max blocks/min | Block-cap runs | Switch/steady reward per hash |\n| --- | --- | ---: | --- | ---: | ---: | ---: |");
    let mut recovery_rows = Vec::new();
    for scenario in scenarios() {
        for (label, half_life_ms) in [("30m", 1_800_000), ("1h", 3_600_000), ("3h", 10_800_000)] {
            let runs: Vec<_> = (0..scenario.runs)
                .map(|index| {
                    simulate(
                        &scenario,
                        half_life_ms,
                        SEED ^ (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15),
                    )
                })
                .collect();
            let mut intervals: Vec<_> = runs
                .iter()
                .flat_map(|run| run.intervals.iter().copied())
                .collect();
            let median = quantile(&mut intervals, 0.5);
            let p95 = quantile(&mut intervals, 0.95);
            let maximum = *intervals.last().unwrap();
            let burst = runs
                .iter()
                .map(|run| run.max_blocks_per_minute)
                .max()
                .unwrap();
            let capped = runs.iter().filter(|run| run.budget_censored).count();
            let switching_rewards: f64 =
                runs.iter().map(|run| run.switching_expected_rewards).sum();
            let switching_work: f64 = runs.iter().map(|run| run.switching_hash_seconds).sum();
            let steady_rewards: f64 = runs.iter().map(|run| run.steady_expected_rewards).sum();
            let steady_work: f64 = runs.iter().map(|run| run.elapsed).sum();
            let profitability = if scenario.compare_switching && switching_work > 0.0 {
                format!(
                    "{:.3}x",
                    (switching_rewards / switching_work) / (steady_rewards / steady_work)
                )
            } else {
                "n/a".into()
            };
            println!(
                "| {} | {} | {} | {} / {} / {} | {} | {}/{} | {} |",
                scenario.name,
                label,
                intervals.len(),
                duration(median),
                duration(p95),
                duration(maximum),
                burst,
                capped,
                scenario.runs,
                profitability
            );
            if scenario.recovery_from.is_some() {
                let first: Vec<_> = runs.iter().map(|run| run.first_post_drop).collect();
                let recovery: Vec<_> = runs.iter().map(|run| run.recovery).collect();
                recovery_rows.push(format!(
                    "| {} | {} | {} | {} |",
                    scenario.name,
                    label,
                    optional_quantiles(&first),
                    optional_quantiles(&recovery)
                ));
            }
        }
    }
    println!("\n| Departure scenario | Half-life | First post-drop block: median / p95 | Observed in-band target: median / p95 |\n| --- | --- | --- | --- |");
    for row in recovery_rows {
        println!("{row}");
    }
    println!("\nThe 10000x fixed-parent departure has a first-block mean of 600000 seconds (6.944 days), median of {:.3} days and p95 of {:.3} days before considering censoring. These distribution values follow the unchanged target and exponential waiting model and are identical for every half-life. Later target recovery must not be substituted for this first-block delay.", 600_000.0 * 2.0f64.ln() / DAY, -600_000.0 * 0.05f64.ln() / DAY);
    println!("\nInterpretation: compare ordinary variance, post-shock delay, bursts and the specified switching policy together. These bounded cases can support choosing a pre-mainnet candidate; they do not establish an optimal half-life, resistance to every mining strategy, or a global economic equilibrium.");
}
