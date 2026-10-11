# Hegemon v0.10.2 — public testnet difficulty correction

This maintenance release is based on the published v0.10.1 release and targets the existing public v0.10 testnet running on hegemon-ovh. It retains the synchronization, mining-gate, wallet snapshot and dependency fixes from v0.10.1. The testnet genesis, node/wallet data formats and proof-backend review posture are retained.

## Mandatory upgrade before block 120,000

The existing rule retargets every ten blocks but measures nine elapsed block intervals against a ten-minute denominator. At uniform 60-second intervals, this measures 540 seconds against 600 seconds and unnecessarily reduces the target by 10%.

The corrected rule measures ten elapsed intervals against the same 600,000-ms denominator. For a retarget block at height `H`, it uses `timestamp[H-1] - timestamp[H-11]`; legacy validation uses `timestamp[H-1] - timestamp[H-10]`. The ten-block cadence, first retarget at height 20, 60-second target, compact encoding and 150,000..2,400,000-ms timespan clamps are retained.

**All public-testnet node operators and miners must upgrade to v0.10.2 before the chain reaches block 120,000.** The compiled consensus constant `RETARGET_CORRECTION_ACTIVATION_HEIGHT: Option<u64>` is `Some(120_000)`. Historical blocks below height 120,000 retain legacy validation; block 120,000 and later eligible retarget boundaries use the corrected rule. Mining and validation use the same schedule, with no environment-variable or command-line override.

Upgrade from v0.10.0 or v0.10.1 before activation while retaining your existing node data directory and wallet store. Older nodes do not implement this schedule and will reject a corrected block whenever its expected bits differ from their legacy calculation. Running an older miner after activation can produce an incompatible fork. Activation is determined by block height; calendar estimates are planning guidance and must not be treated as the upgrade deadline.

This is a maintenance release for the existing public testnet only. It retains the v0.10.1 fixes and existing chain identity without introducing the newer development-network consensus.

## Testnet operation

The node, wallet and wallet daemon identify as 0.10.2. Download the **hegemon-testnet-0.10.2 ZIP for your platform**, verify its accompanying SHA-256 checksum, and extract it. On Windows, run `testnet-start.cmd`; on Linux or macOS, run `bash testnet-start.sh`. The launcher supplies testnet seeds and persistent local data and starts with mining disabled. Read `TESTNET-README.txt` for chain comparison, existing data, wallet and optional mining instructions.

The testnet genesis is `0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59`. The OVH seed is `hegemon.pauli.group:30333`; the second documented seed is reserved for development and may refuse the testnet connection. Canonical catch-up requires successful peers and a matching block hash at a shared height.

Keep existing node and wallet data, choose an existing node path explicitly when updating, and enable system time synchronization before mining. A failed wallet scan does not establish a zero on-chain balance. This release remains a maintenance update for the existing public testnet.
