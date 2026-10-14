# Hegemon v0.10.3 — public testnet wallet and launcher maintenance

This maintenance release is based on the published v0.10.2 release and targets the existing public v0.10 testnet. It retains the synchronization, mining-gate, wallet snapshot/source-cache and difficulty correction from earlier maintenance releases. The testnet genesis, node/wallet data formats, activation schedule and proof-backend review posture are retained.

## Wallet RPC transport

The native node serves HTTP JSON-RPC. One-shot wallet synchronization, status and send instructions use `http://127.0.0.1:9944`; the compatibility flag `--ws-url` and walletd field `ws_url` retain their existing names. Corrected operator runbooks and join skills no longer direct one-shot sync to the unsupported native WebSocket endpoint. Use your existing wallet store and allow a scan to complete before interpreting cached balances. A failed scan does not establish a zero on-chain balance. Desktop sync uses a shared two-hour session deadline, with cancellation retained, so a healthy first historical scan is not stopped by the previous short watchdogs. The reset option applies when the chain genesis changed; it does not force a same-chain scan from zero.

## Windows launcher without an execution-policy override

`testnet-start.cmd` starts the packaged native node directly and no longer invokes PowerShell. The Windows bundle contains no PowerShell helper and requires no execution-policy change. Relay is the default; mining still requires your existing public payout address, synchronized time and canonical-chain verification. The optional `-Status` action uses Windows 10/11 `curl.exe` for bounded local HTTP queries.

A reviewed launcher hash policy is checked at build, native-manifest, assembly and download-packaging boundaries. It rejects changed or unlisted helpers and execution-policy weakening in the bounded release producers. This is a release-helper policy gate, not a general shell-code or supply-chain security proof. Windows behavior must pass the Windows release job before publication; portable source tests do not substitute for that execution.

## Dependency maintenance

The release lockfile updates `quinn-proto` from 0.11.16 to the upstream patched 0.11.18 version for newly published denial-of-service advisories. No new dependency-audit exceptions are added.

## Retained difficulty correction

v0.10.2 introduced the corrected ten-interval difficulty measurement at block 120,000. v0.10.3 retains exactly that schedule: historical blocks below 120,000 use legacy validation, and eligible retarget boundaries at and after activation use the corrected rule. Mining and validation share the same schedule, without a command-line or environment override. Nodes already on v0.10.2 share these consensus rules; v0.10.0/v0.10.1 do not implement the activation schedule and can diverge after activation.

## Testnet operation

Download the **hegemon-testnet-0.10.3 ZIP for your platform**, verify its accompanying SHA-256 checksum, and extract it. On Windows, run `testnet-start.cmd`; on Linux or macOS, run `bash testnet-start.sh`. Keep your existing node data directory and wallet store. The launcher supplies the documented testnet seeds, persistent data and mining disabled by default. Read `TESTNET-README.txt` for status, wallet and optional mining instructions.

The testnet genesis remains `0x506fc2cd5ed367cc68d6d23a987fe6e4a7916fde02a249105ab91884a1e6fa59`. The OVH seed is `hegemon.pauli.group:30333`; the second documented seed is reserved for development and may refuse the testnet connection. Successful peers and matching hashes at a shared height establish canonical catch-up. Enable system time synchronization before mining.

All required source, formal, dependency, native-backend, platform, packaging and downloaded-artifact gates remain publication requirements. This source preparation does not claim those gates have completed for v0.10.3.
