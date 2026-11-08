# Bounded ASERT scenarios

Run: `cargo run --release -p consensus-light-client --example asert_scenarios`

Actual integer ASERT API; 60-second spacing; fixed anchor height 1, anchor-parent time 0, anchor time 60000 ms, reference bits 0x1d00ffff. Hegemon's existing target limit remains 0x207fffff. Half-lives: 30 minutes, 1 hour, 3 hours.

SplitMix64 base seed 0x48474e4153455254; run i uses base XOR ((i+1)*0x9e3779b97f4a7c15) with wrapping multiplication. Each half-life receives the same seed set. Exponential hazard is integrated across wall-clock hashrate changes; timestamps round up to milliseconds and advance at least 1 ms.

Normal scenarios: 32 runs each, 12 hours. Arrival/departure: 1x until hour 3, 10x until hour 6, then persistent 1x. Switching: after hour 3, alternate 10x and 1x every 30 minutes. Extreme departure: 8 runs from the identical fixed parent, persistent 0.0001x hash rate, up to 45 days. Every run stops at 4096 blocks; capped runs are reported.

Interval statistics pool all observed intervals, including initial and transition intervals. They omit the unfinished final waiting interval and are therefore conditional on observed blocks. Quantiles use nearest rank. Maximum burst counts blocks within a sliding 60-second interval. Recovery means the first post-drop target with conditional expected interval in [30,120] seconds; it does not establish sustained steady production. Censored means no such observation before the horizon or block cap. Recovery quantiles use only uncensored runs; with substantial censoring they are not estimates of the full recovery distribution.

Switch/steady reward per hash compares a unit baseline miner present throughout with nine extra units present only in high phases. Rewards are expected proportional allocations conditional on observed blocks; exposure is integrated in hash-seconds. Reward value is constant, fees absent, and no switching strategy is optimized.

This finite idealized experiment omits network latency, orphaning, transaction processing, price feedback and strategic timestamp manipulation. In particular, catch-up burst counts are controller behavior under those assumptions, not achievable node throughput or a security proof.

| Scenario | Half-life | Blocks | Interval median / p95 / max | Max blocks/min | Block-cap runs | Switch/steady reward per hash |
| --- | --- | ---: | --- | ---: | ---: | ---: |
| steady 1x | 30m | 23011 | 41.685 s / 3.02 min / 10.75 min | 8 | 0/32 | n/a |
| steady 1x | 1h | 22992 | 41.723 s / 3.01 min / 11.07 min | 8 | 0/32 | n/a |
| steady 1x | 3h | 22970 | 41.854 s / 3.00 min / 11.15 min | 8 | 0/32 | n/a |
| 10x arrival then departure | 30m | 23013 | 35.113 s / 3.16 min / 1.07 h | 17 | 0/32 | 0.241x |
| 10x arrival then departure | 1h | 23296 | 29.227 s / 3.45 min / 50.66 min | 18 | 0/32 | 0.375x |
| 10x arrival then departure | 3h | 29213 | 16.369 s / 3.20 min / 45.48 min | 20 | 0/32 | 0.705x |
| repeated 10x switching | 30m | 24912 | 25.269 s / 3.12 min / 33.88 min | 17 | 0/32 | 0.519x |
| repeated 10x switching | 1h | 27287 | 22.121 s / 2.95 min / 31.65 min | 18 | 0/32 | 0.560x |
| repeated 10x switching | 3h | 35779 | 15.565 s / 2.42 min / 25.61 min | 20 | 0/32 | 0.672x |
| 10000x departure at fixed parent | 30m | 32768 | 0.001 s / 58.212 s / 20.54 d | 4096 | 8/8 | n/a |
| 10000x departure at fixed parent | 1h | 32768 | 0.001 s / 1.17 min / 20.54 d | 4096 | 8/8 | n/a |
| 10000x departure at fixed parent | 3h | 32768 | 0.001 s / 1.70 min / 20.54 d | 4096 | 8/8 | n/a |

| Departure scenario | Half-life | First post-drop block: median / p95 | Observed in-band target: median / p95 |
| --- | --- | --- | --- |
| 10x arrival then departure | 30m | 9.64 min / 28.58 min; 0/32 censored | 1.62 h / 1.76 h; 0/32 censored |
| 10x arrival then departure | 1h | 5.13 min / 28.93 min; 0/32 censored | 2.94 h / 3.21 h; 0/32 censored |
| 10x arrival then departure | 3h | 4.33 min / 19.41 min; 0/32 censored | 5.79 h / 5.92 h; 28/32 censored |
| 10000x departure at fixed parent | 30m | 4.62 d / 20.54 d; 0/8 censored | 14.99 h / 2.62 d; 6/8 censored |
| 10000x departure at fixed parent | 1h | 4.62 d / 20.54 d; 0/8 censored | 2.63 d / 3.34 d; 5/8 censored |
| 10000x departure at fixed parent | 3h | 4.62 d / 20.54 d; 0/8 censored | 2.73 d / 3.42 d; 5/8 censored |

The 10000x fixed-parent departure has a first-block mean of 600000 seconds (6.944 days), median of 4.814 days and p95 of 20.804 days before considering censoring. These distribution values follow the unchanged target and exponential waiting model and are identical for every half-life. Later target recovery must not be substituted for this first-block delay.

Interpretation: compare ordinary variance, post-shock delay, bursts and the specified switching policy together. These bounded cases can support choosing a pre-mainnet candidate; they do not establish an optimal half-life, resistance to every mining strategy, or a global economic equilibrium.
