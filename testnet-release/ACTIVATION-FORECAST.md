# v0.10.2 activation schedule and planning forecast

**The selected public-testnet activation height is block 120,000.** v0.10.2 compiles `RETARGET_CORRECTION_ACTIVATION_HEIGHT = Some(120_000)`. All public-testnet node operators and miners must upgrade before the chain reaches that height. Historical blocks below 120,000 retain legacy validation; eligible retarget boundaries beginning with 120,000 use ten elapsed intervals. The activation constant has no local environment or CLI override.

Using the historical anchor below, reaching block 120,000 would take approximately:

| Constant interval scenario | Estimated time of block 120,000 |
|---|---|
| 60 seconds per block | 2026-10-13 04:17 UTC |
| Measured 72.88252 seconds per block | 2026-10-13 15:38 UTC |
| 90 seconds per block | 2026-10-14 06:43 UTC |

These estimates use the October 10 snapshot and are not a live countdown, statistical confidence interval or promised deadline. Additional hash power or other changes can move activation earlier than any listed scenario. Use the live chain height to schedule upgrades.

## Historical planning snapshot

Live testnet anchor: block **116,829**, block timestamp **2026-10-10 23:26:48 UTC**, read at **2026-10-10 23:27:46 UTC** from hegemon-ovh loopback RPC. Genesis matches the testnet: `0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59`.

Expected heights extrapolate the measured last-day mean of **72.88252 seconds per block** (1,184 intervals ending at block 116,813). All heights are rounded upward to a multiple of **10**, so they align with existing retarget boundaries.

| Original planning date (UTC) | Height at observed pace | Planning range, 90 to 60 s/block |
|---|---:|---:|
| 2026-10-11 00:00 | 116,860 | 116,860–116,870 |
| 2026-10-11 12:00 | 117,450 | 117,340–117,590 |
| 2026-10-12 00:00 | 118,050 | 117,820–118,310 |
| 2026-10-12 12:00 | 118,640 | 118,300–119,030 |
| 2026-10-13 00:00 | 119,230 | 118,780–119,750 |
| 2026-10-13 12:00 | 119,820 | 119,260–120,470 |
| 2026-10-14 00:00 | 120,420 | 119,740–121,190 |
| 2026-10-14 12:00 | 121,010 | 120,220–121,910 |
| 2026-10-15 00:00 | 121,600 | 120,700–122,630 |
| 2026-10-15 12:00 | 122,200 | 121,180–123,350 |
| 2026-10-16 00:00 | 122,790 | 121,660–124,070 |
| 2026-10-16 12:00 | 123,380 | 122,140–124,790 |
| 2026-10-17 00:00 | 123,970 | 122,620–125,510 |
| 2026-10-17 12:00 | 124,570 | 123,100–126,230 |

Calculation: `ceil((116829 + seconds_since_anchor / seconds_per_block) / 10) * 10`.

The original planning scenarios above assume a constant mean interval before activation. Mining luck, added or removed hash power, retargeting, outages and reorgs can move the date. The correction starts at the selected block height 120,000; it does not change earlier blocks. These calculations are retained as historical planning evidence. The release must bind the committed activation constant in its rebuilt binaries and source-bound review archive and pass its release gates before publication. No gate result or current live height is established by this forecast.
