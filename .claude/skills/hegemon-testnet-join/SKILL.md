---
name: hegemon-testnet-join
description: Join the Hegemon testnet using the native 0.10 launch profile, verify genesis, sync to the tip, and choose relay or mining mode on the shipped recursive-block path.
compatibility: Requires ./target/release/hegemon-node, network access to hegemon.pauli.group:30333, synchronized host time for mining, and ./target/release/walletd only when opening a wallet or exporting a mining address.
metadata:
  repo: Reflexivity/Hegemon
  version: "1.6"
---

# Goal
Connect a Claude-assisted operator or end user to the public Hegemon 0.10 testnet without SSH, verify that the node is on the canonical chain, and enable mining only when this host is meant to author blocks.

# Defaults
- Network name: `Hegemon`.
- Approved public join seed list: `hegemon.pauli.group:30333`.
- Native profile: `--dev` on the 0.10 release binary. Do not use removed 0.9 JSON chainspec files, `config/dev-chainspec.json`, or `--chain`.
- Default role: relay node / full node. Use mining mode only for an authoring host with a deliberate shielded payout address.
- RPC port: `9944` for CLI examples.
- P2P listen port: `30333` for a single host. Pick another local port if `30333` is already in use.
- Shipped block path: native `tx_leaf` artifacts plus same-block `recursive_block_v2`. Legacy `InlineTx` is not the product path.

# Steps
1. Ensure binaries exist. Fresh clones must run setup before starting a node:
   - `make setup`
   - `make node`
   - `cargo build --release -p walletd` only if wallet or mining-address operations are needed.
2. Confirm host time is synchronized before authoring. PoW block import rejects future-skewed timestamps.
   - macOS: `sudo systemsetup -getusingnetworktime`
   - Linux: `timedatectl status` or `chronyc tracking`
3. Start a relay node first. This is the normal no-SSH join path for laptops and wallet users:
   - `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333" \`
   - `HEGEMON_PQ_STRICT_COMPATIBILITY=1 \`
   - `./target/release/hegemon-node \`
   - `  --dev \`
   - `  --base-path ~/.hegemon-node \`
   - `  --port 30333 \`
   - `  --rpc-port 9944 \`
   - `  --rpc-methods unsafe \`
   - `  --name "HegemonRelay"`
   - Keep RPC on loopback for normal wallet and desktop use. Do not add `--rpc-external` unless intentionally exposing RPC; exposed RPC must use `--rpc-methods safe`.
4. Enable mining only for an authoring node with a known payout address:
   - `export HEGEMON_MINER_ADDRESS=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "YOUR_PASSPHRASE" \`
   - `  | ./target/release/walletd --store ~/.hegemon-wallet --mode open \`
   - `  | jq -r '.result.primaryAddress')`
   - Restart the node with mining enabled:
   - `HEGEMON_MINE=1 \`
   - `HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333" \`
   - `HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \`
   - `HEGEMON_PQ_STRICT_COMPATIBILITY=1 \`
   - `./target/release/hegemon-node \`
   - `  --dev \`
   - `  --base-path ~/.hegemon-node \`
   - `  --port 30333 \`
   - `  --rpc-port 9944 \`
   - `  --rpc-methods unsafe \`
   - `  --name "HegemonAuthor"`
   - Mining pauses while syncing and resumes only once caught up. All miners must use the same approved seed list to avoid partitions and forks.
5. Monitor sync status, height, peers, and local profile:
   - `curl -s -H "Content-Type: application/json" -d '{"id":1,"jsonrpc":"2.0","method":"system_health"}' http://127.0.0.1:9944 | jq`
   - `curl -s -H "Content-Type: application/json" -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' http://127.0.0.1:9944 | jq`
   - `curl -s -H "Content-Type: application/json" -d '{"id":1,"jsonrpc":"2.0","method":"system_peers"}' http://127.0.0.1:9944 | jq`
   - `curl -s -H "Content-Type: application/json" -d '{"id":1,"jsonrpc":"2.0","method":"hegemon_nodeConfig"}' http://127.0.0.1:9944 | jq`
6. If height stalls, compare genesis with a trusted synced node:
   - `curl -s -H "Content-Type: application/json" -d '{"id":1,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[0]}' http://127.0.0.1:9944 | jq`
   - The returned genesis must match the already-synced trusted node on the same native release/profile.
7. Sync wallet notes against the local node RPC:
   - `printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:9944","force_rescan":false}}\n' "YOUR_PASSPHRASE" \`
   - `  | ./target/release/walletd --store ~/.hegemon-wallet --mode open`

# Notes
- The approved public 0.10 bootstrap list is `hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333`. Do not substitute legacy hostnames or raw IPs; peers learn additional public endpoints through P2P discovery.
- Keep host clock sync enabled with NTP or chrony. PoW import rejects future-skewed timestamps.
- If genesis differs, stop the node and wipe the base path before restarting with the matching release/profile.
- Do not enter a public node RPC address into the desktop app. Run a local relay node with the approved seed and let the desktop connect to localhost.
- Do not provision `hegemon-prover` or `hegemon-prover-worker` for a normal testnet join. The live path uses local native tx-leaf verification plus same-block `recursive_block_v2` artifacts.
