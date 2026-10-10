# Hegemon v0.10.2 — public testnet retarget candidate

This candidate is based on the published v0.10.1 maintenance release and joins the existing v0.10 testnet running on hegemon-ovh. It retains the synchronization, mining-gate, wallet snapshot and dependency fixes from v0.10.1. The testnet genesis, node/wallet data formats and proof-backend review posture are retained.

## Retarget correction and activation status

The existing rule retargets every ten blocks but measures nine elapsed block intervals against a ten-minute denominator. At uniform 60-second intervals, this measures 540 seconds against 600 seconds and unnecessarily reduces the target by 10%.

The corrected rule measures ten elapsed intervals against the same 600,000-ms denominator. For a retarget block at height `H`, it uses `timestamp[H-1] - timestamp[H-11]`; legacy validation uses `timestamp[H-1] - timestamp[H-10]`. The ten-block cadence, first retarget at height 20, 60-second target, compact encoding and 150,000..2,400,000-ms timespan clamps are retained.

**The activation height has not been selected.** The compiled consensus constant `RETARGET_CORRECTION_ACTIVATION_HEIGHT: Option<u64>` is currently `None`, so this preparation uses legacy validation at every height. There is no environment-variable or command-line override. Once an agreed height is committed, historical blocks before it retain legacy validation and eligible retarget boundaries at/after it use the corrected rule. Mining and validation use the same schedule.

This candidate has not been published and the correction is not active. Before tagging or publishing v0.10.2, select and commit the agreed activation height, rebuild the shipped binaries, regenerate the source-bound review archive and pass all release gates. Operators must receive the same activation schedule and coordinated upgrade instructions; existing users should keep the published v0.10.1 release until then.

## Testnet operation

The node, wallet and wallet daemon identify as 0.10.2. When the final release is published, download the **hegemon-testnet-0.10.2 ZIP for your platform**, verify its accompanying SHA-256 checksum, and extract it. On Windows, run `testnet-start.cmd`; on Linux or macOS, run `bash testnet-start.sh`. The launcher supplies testnet seeds and persistent local data and starts with mining disabled. Read `TESTNET-README.txt` for chain comparison, existing data, wallet and optional mining instructions.

The testnet genesis is `0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59`. The OVH seed is `hegemon.pauli.group:30333`; the second documented seed is reserved for development and may refuse the testnet connection. Canonical catch-up requires successful peers and a matching block hash at a shared height.

Keep existing node and wallet data, choose an existing node path explicitly when updating, and enable system time synchronization before mining. A failed wallet scan does not establish a zero on-chain balance. This release remains a maintenance update for the existing public testnet.
