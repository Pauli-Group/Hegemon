# Hegemon v0.10.1 — public testnet maintenance

This release joins the existing v0.10 testnet running on hegemon-ovh. It includes the synchronization and mining-gate fixes from commit `b819911dbf6d045501a3526da1268f1fa83092ea`, without switching to the newer development network or Bitcoin80 consensus.

The old v0.10.0 binaries could stall when a fresh node received only the first 256 blocks of a 512-block request. This maintenance build uses bounded 64-block requests, resumes from verified progress, paces follow-up pages, and keeps mining paused while the verified peer target is ahead.

Wallet commitment pages now stay within the note snapshot captured at the beginning of a scan. New blocks arriving during a scan are picked up on the next pass, rather than causing a commitment-count mismatch and an unnecessary scan-cache reset.

Download the **hegemon-testnet-0.10.1 ZIP for your platform**, verify its accompanying SHA-256 checksum, and extract it. On Windows, run `testnet-start.cmd`; on Linux or macOS, run `bash testnet-start.sh`. The launcher supplies testnet seeds and persistent local data, and starts with mining disabled. Read `TESTNET-README.txt` for status, existing data, wallet, and optional mining instructions.

The testnet genesis is `0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59`. The OVH seed is `hegemon.pauli.group:30333`; the second documented seed is currently reserved for development and may refuse the testnet connection. Canonical catch-up still requires successful peers and a matching block hash at a shared height.

The bare node executable now chooses the documented testnet seeds on a normal launch when HEGEMON_SEEDS is unset; explicit seed settings and isolated dev/tmp runs retain their existing behavior. The ZIP launcher is recommended for stable home-directory storage and status commands.

The node, wallet and wallet daemon identify as 0.10.1. A narrow dependency update fixes RUSTSEC-2026-0285 in rustls. Existing node and wallet data are preserved; choose an existing node path explicitly when updating. This release is for the existing testnet and retains the baseline proof-backend review posture.
