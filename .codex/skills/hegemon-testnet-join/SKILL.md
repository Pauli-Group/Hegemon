---
name: hegemon-testnet-join
description: Join the Hegemon testnet using the shared chainspec, verify genesis, sync to the tip, and enable mining safely.
compatibility: Requires ./target/release/hegemon-node, ./target/release/walletd, network access to hegemon.pauli.group:30333, and a shared chainspec at config/dev-chainspec.json.
metadata:
  repo: Reflexivity/Hegemon
  version: "1.1"
---

# Goal
Connect a new node to the Hegemon testnet, verify it is on the canonical chain, and mine only after sync completes.

# Defaults
- Approved public seed list: hegemon.pauli.group:30333,158.69.222.121:30333
- Chain spec: config/dev-chainspec.json
- Chainspec SHA-256: 455f552ec9e73bb07ad95ac8b9bf03c72461acc16ffd9afe738b70c31cce3cc1
- Genesis hash: 0x15202f417428013d3069f19110043e98c58fc0a943781c5713393b5153413839
- RPC port: 9944
- P2P listen: /ip4/0.0.0.0/tcp/30333

# Steps
1. Ensure binaries exist (fresh clones must run make setup and make node):
   - make setup
   - make node
   - cargo build --release -p walletd
2. Verify the shared chainspec matches the boot node. Do not use --chain dev.
   - shasum -a 256 config/dev-chainspec.json
   - Expected: 455f552ec9e73bb07ad95ac8b9bf03c72461acc16ffd9afe738b70c31cce3cc1
3. Create or open a wallet and export the shielded mining address:
   - export HEGEMON_MINER_ADDRESS=$(printf '%s\n{"id":1,"method":"status.get","params":{}}\n' "YOUR_PASSPHRASE" \
     | ./target/release/walletd --store ~/.hegemon-wallet --mode open \
     | jq -r '.result.primaryAddress')
4. Start the node with the shared chainspec and seed:
   - HEGEMON_MINE=1 \
     HEGEMON_SEEDS="hegemon.pauli.group:30333,158.69.222.121:30333" \
     HEGEMON_MINER_ADDRESS="$HEGEMON_MINER_ADDRESS" \
     HEGEMON_PROVER_REWARD_ADDRESS="$HEGEMON_MINER_ADDRESS" \
     HEGEMON_PQ_STRICT_COMPATIBILITY=1 \
     ./target/release/hegemon-node \
       --dev \
       --base-path ~/.hegemon-node \
       --chain config/dev-chainspec.json \
       --listen-addr /ip4/0.0.0.0/tcp/30333 \
       --rpc-port 9944 \
       --rpc-external \
       --rpc-methods safe \
       --name "TestnetNode"
   - If this host is the public authoring node for proof-sidecar / aggregation traffic, also set:
     HEGEMON_AGGREGATION_PROOFS=1
     HEGEMON_BATCH_JOB_TIMEOUT_MS=3600000
     HEGEMON_PROVER_WORK_PACKAGE_TTL_MS=3600000
     HEGEMON_AGG_HOLD_MINING_WHILE_PROVING=1
     HEGEMON_PROVER_WORKERS=0
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
7. Sync wallet notes against the node RPC:
   - printf '%s\n{"id":1,"method":"sync.once","params":{"ws_url":"ws://127.0.0.1:9944","force_rescan":false}}\n' "YOUR_PASSPHRASE" \
     | ./target/release/walletd --store ~/.hegemon-wallet --mode open

# Notes
- All miners should use the exact same `HEGEMON_SEEDS` list to avoid accidental forks/partitions. Keep private peer IPs out of public docs.
- Keep host clock sync enabled (NTP/chrony). PoW import rejects future-skewed timestamps.
- Public authors using an external prover must leave `HEGEMON_AGG_HOLD_MINING_WHILE_PROVING=1` so long recursive proofs do not get invalidated by self-mined empty blocks on new parents.
- If the genesis hash or chainspec differ, stop the node and wipe the base path before restarting.
- Keep RPC access locked down if you expose it beyond localhost.
