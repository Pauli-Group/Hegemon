---
name: hegemon-testnet-join
description: Join the Hegemon testnet using the native 0.10 launch profile, verify genesis, sync to the tip, and enable mining safely on the live InlineTx path.
compatibility: Requires ./target/release/hegemon-node, ./target/release/walletd, network access to devnet.hegemonprotocol.com:30333, and synchronized host time.
metadata:
  repo: Reflexivity/Hegemon
  version: "1.5"
---

# Goal
Connect a new node to the Hegemon testnet, verify it is on the canonical chain, and mine only after sync completes.

# Defaults
- Approved public join seed list: devnet.hegemonprotocol.com:30333
- Native profile: `--dev` on the 0.10 release binary. The 0.9 JSON chainspec files are not part of the native 0.10 launch surface.
- RPC port: 9944
- P2P listen port: 30333

# Steps
1. Ensure binaries exist (fresh clones must run make setup and make node):
   - make setup
   - make node
   - cargo build --release -p walletd
2. Confirm host time is synchronized before authoring. PoW block import rejects future-skewed timestamps.
   - macOS: `sudo systemsetup -getusingnetworktime`
   - Linux: `timedatectl status` or `chronyc tracking`
3. Create or open a wallet and export the shielded mining address:
   - export HEGEMON_MINER_ADDRESS=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "YOUR_PASSPHRASE" \
     | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
     | jq -r '.result.primaryAddress')
4. Start the node with the native profile and approved seed:
   - HEGEMON_MINE=1 \
     HEGEMON_SEEDS="devnet.hegemonprotocol.com:30333" \
     HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \
     HEGEMON_PQ_STRICT_COMPATIBILITY=1 \
     ./target/release/hegemon-node \
       --dev \
       --base-path ~/.hegemon-node \
       --port 30333 \
       --rpc-port 9944 \
       --rpc-external \
       --rpc-methods safe \
       --name "TestnetNode"
   - This is the live InlineTx path. Do not provision `hegemon-prover`, `hegemon-prover-worker`, or proof-sidecar / recursive flags for a normal testnet join.
   - If you are bringing up the first public authoring node after a fresh reset, omit `HEGEMON_SEEDS` or exclude the node's own public address until that first node is already live.
5. Monitor sync status and height. Mining pauses while syncing and resumes once caught up.
   - curl -s -H "Content-Type: application/json" \
     -d '{"id":1,"jsonrpc":"2.0","method":"system_health"}' \
     http://127.0.0.1:9944 | jq
   - curl -s -H "Content-Type: application/json" \
     -d '{"id":1,"jsonrpc":"2.0","method":"hegemon_consensusStatus"}' \
     http://127.0.0.1:9944 | jq
   - curl -s -H "Content-Type: application/json" \
     -d '{"id":1,"jsonrpc":"2.0","method":"chain_getHeader"}' \
     http://127.0.0.1:9944 | jq
6. If height stalls, check peers and genesis hash:
   - curl -s -H "Content-Type: application/json" \
     -d '{"id":1,"jsonrpc":"2.0","method":"chain_getBlockHash","params":[0]}' \
     http://127.0.0.1:9944 | jq
   - The returned genesis must match the already-synced trusted authoring node on the same native release/profile.
7. Sync wallet notes against the node RPC:
   - printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:9944","force_rescan":false}}\n' "YOUR_PASSPHRASE" \
     | ./target/release/walletd --store ~/.hegemon-wallet --mode open

# Notes
- All miners should use the exact same `HEGEMON_SEEDS` list to avoid accidental forks/partitions. Keep private peer IPs out of public docs.
- The canonical public 0.10 dev join seed is `devnet.hegemonprotocol.com:30333`. Do not list legacy hostnames or raw IPs separately as fake redundancy.
- Keep host clock sync enabled (NTP/chrony). PoW import rejects future-skewed timestamps.
- If the genesis hash differs, stop the node and wipe the base path before restarting with the matching release/profile.
- Keep RPC access locked down if you expose it beyond localhost.
