# v0.10.2 activation-height planning forecast

Live testnet anchor: block **116,829**, block timestamp **2026-10-10 23:26:48 UTC**, read at **2026-10-10 23:27:46 UTC** from hegemon-ovh loopback RPC. Genesis matches the testnet: `0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59`.

Expected heights extrapolate the measured last-day mean of **72.88252 seconds per block** (1,184 intervals ending at block 116,813). All heights are rounded upward to a multiple of **10**, so they align with existing retarget boundaries.

| Intended activation date (UTC) | Height at observed pace | Planning range, 90 to 60 s/block |
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

These are planning scenarios, not statistical confidence bounds or promised activation times. The scenarios assume a constant mean interval before activation; mining luck, added or removed hash power, retargeting, outages and reorgs can move the date. The fix affects pace only after its selected height. Refresh against the live height and trailing rate shortly before choosing a height, then allow adequate client-upgrade lead time. No activation height is chosen or compiled by this forecast.
