# Substrate Integration Testing Protocol

**Version**: 1.0.0  
**Last Updated**: 2025-11-25  
**Status**: Active  
**Owner**: Core Team

---

## Overview

This document provides the complete testing protocol for the Hegemon Substrate migration. It covers:

1. **Automated tests** - Can be run via `cargo test`
2. **Semi-automated tests** - Require manual node startup but automated verification
3. **Manual integration tests** - Require human observation and multiple terminals

---

## Quick Reference

| Test Suite | Command | Duration | Automation Level |
|------------|---------|----------|------------------|
| Unit Tests | `./scripts/test-substrate.sh unit` | ~2 min | ✅ Fully Automated |
| Substrate Tests | `./scripts/test-substrate.sh substrate` | ~3 min | ✅ Fully Automated |
| PQ Network Tests | `./scripts/test-substrate.sh pq` | ~2 min | ✅ Fully Automated |
| Single Node Mining | `./scripts/test-substrate.sh single-node` | ~2 min | ⚡ Semi-Automated |
| Two Node Sync | `./scripts/test-substrate.sh two-node` | ~3 min | ⚠️ Manual Required |
| Three Node Consensus | `./scripts/test-substrate.sh three-node` | ~5 min | ⚠️ Manual Required |
| Partition Recovery | `./scripts/test-substrate.sh partition` | ~10 min | ⚠️ Manual Required |
| Full Suite | `./scripts/test-substrate.sh all` | ~30 min | ⚠️ Manual Required |

---

## Prerequisites

### System Requirements

- **OS**: macOS or Linux
- **RAM**: 8GB minimum (16GB recommended for multi-node tests)
- **Disk**: 2GB free space
- **Ports**: 9944-9946, 30333-30335 available

### Software Requirements

```bash
# Rust toolchain
rustup show  # Should show stable toolchain

# Required tools
which curl jq  # Both must be installed

# Optional (for formal verification)
which tlc apalache-mc  # TLA+ tools
```

### Build the Node

```bash
cd /path/to/hegemon

# Clean build (recommended after cargo clean)
cargo build --release -p hegemon-node --features substrate

# Verify binary exists
ls -la target/release/hegemon-node 2>/dev/null || \
ls -la target/release/substrate_node 2>/dev/null || \
echo "Build the node first!"
```

---

## Part 1: Fully Automated Tests

These tests run entirely via `cargo test` with no manual intervention.

### 1.1 Core Unit Tests

```bash
# Run all workspace unit tests
cargo test --workspace --exclude security-tests

# Expected: All tests pass
# Duration: ~2-5 minutes
```

### 1.2 Substrate Integration Tests (9 tests)

```bash
# Run Substrate-specific unit tests
cargo test -p security-tests --test multi_node_substrate --features substrate

# Expected output:
# test substrate_tests::test_mining_worker_stats ... ok
# test substrate_tests::test_production_config_from_env ... ok
# test substrate_tests::test_production_mining_worker_builder ... ok
# test substrate_tests::test_production_provider_on_new_block ... ok
# test substrate_tests::test_production_provider_import_callback ... ok
# test substrate_tests::test_production_provider_callbacks ... ok
# test substrate_tests::test_block_template_with_transactions ... ok
# test substrate_tests::test_concurrent_imports ... ok
# test substrate_tests::test_transaction_limit_enforcement ... ok
# test result: ok. 9 passed; 0 failed; 4 ignored
```

### 1.3 PQ Network Tests (network crate)

```bash
# Run PQ network transport and handshake tests
cargo test -p network

# Expected: All network tests pass
# Duration: ~1-2 minutes
```

### 1.4 Security Pipeline Tests

```bash
# Run cross-component security tests
export PROPTEST_MAX_CASES=64
cargo test -p security-tests --test security_pipeline -- --nocapture

# Expected: All security assertions pass
```

---

## Part 2: Semi-Automated Tests

These require starting a node, but verification is scripted.

### 2.1 Single Node Boot & Mine Test

**Purpose**: Verify a single node can boot, mine blocks, and respond to RPC.

**Automated Steps**:
```bash
./scripts/test-substrate.sh single-node
```

**Manual Alternative**:

```bash
# Terminal 1: Start node
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=2 \
cargo run --release -p hegemon-node --features substrate -- \
  --dev --tmp --rpc-port 9944 --port 30333

# Terminal 2: Wait 30s, then verify
sleep 30
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result.number'

# SUCCESS: Returns block number > "0x0"
# FAILURE: Returns "0x0" or connection refused
```

**Verification Criteria**:
| Check | Expected | Command |
|-------|----------|---------|
| Node boots | Logs show "Hegemon node started" | Observe terminal |
| Mining active | Logs show "Mining enabled" | Observe terminal |
| Blocks produced | `chain_getHeader` returns number > 0 | RPC call |
| PQ transport ready | Logs show "SubstratePqTransport ready" | Observe terminal |

---

## Part 3: Manual Integration Tests (Multi-Node)

These tests require multiple terminals and human observation.

### 3.1 Two Node Sync Test

**Purpose**: Verify two nodes connect via PQ network and sync blocks.

**Setup**: Open 3 terminal windows.

**Terminal 1 - Node A (Miner)**:
```bash
cd /path/to/hegemon

HEGEMON_MINE=1 HEGEMON_MINE_THREADS=2 \
cargo run --release -p hegemon-node --features substrate -- \
  --dev \
  --tmp \
  --base-path /tmp/hegemon-node-a \
  --rpc-port 9944 \
  --port 30333 \
  --name "NodeA-Miner" \
  --require-pq \
  --pq-verbose
```

Wait for: `"Hegemon node started"` and note the peer ID.

**Terminal 2 - Node B (Syncing)**:
```bash
cd /path/to/hegemon

cargo run --release -p hegemon-node --features substrate -- \
  --dev \
  --tmp \
  --base-path /tmp/hegemon-node-b \
  --rpc-port 9945 \
  --port 30334 \
  --name "NodeB-Sync" \
  --require-pq \
  --bootnodes /ip4/127.0.0.1/tcp/30333
```

**Terminal 3 - Verification**:
```bash
# Wait 30 seconds for sync
sleep 30

echo "=== Node A (Miner) ==="
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result | "Block #\(.number) Hash: \(.hash[0:18])..."'

echo "=== Node B (Sync) ==="
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
  http://127.0.0.1:9945 | jq '.result | "Block #\(.number) Hash: \(.hash[0:18])..."'

# Check peer count
echo "=== Node A Peers ==="
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result | length'

echo "=== Node B Peers ==="
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}' \
  http://127.0.0.1:9945 | jq '.result | length'
```

**Success Criteria**:
- [ ] Both nodes show "PQ peer connected" in logs
- [ ] Node B's block height catches up to Node A
- [ ] Both nodes report 1 peer
- [ ] Block hashes match between nodes

**Cleanup**:
```bash
# Press Ctrl+C in Terminal 1 and Terminal 2
rm -rf /tmp/hegemon-node-a /tmp/hegemon-node-b
```

---

### 3.2 Three Node Consensus Test

**Purpose**: Verify three nodes form a network and maintain consensus with competing miners.

**Setup**: Open 4 terminal windows.

**Terminal 1 - Node A**:
```bash
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \
cargo run --release -p hegemon-node --features substrate -- \
  --dev --tmp --base-path /tmp/node-a \
  --rpc-port 9944 --port 30333 --name "NodeA" --require-pq
```

**Terminal 2 - Node B**:
```bash
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \
cargo run --release -p hegemon-node --features substrate -- \
  --dev --tmp --base-path /tmp/node-b \
  --rpc-port 9945 --port 30334 --name "NodeB" --require-pq \
  --bootnodes /ip4/127.0.0.1/tcp/30333
```

**Terminal 3 - Node C**:
```bash
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \
cargo run --release -p hegemon-node --features substrate -- \
  --dev --tmp --base-path /tmp/node-c \
  --rpc-port 9946 --port 30335 --name "NodeC" --require-pq \
  --bootnodes /ip4/127.0.0.1/tcp/30333 \
  --bootnodes /ip4/127.0.0.1/tcp/30334
```

**Terminal 4 - Monitor**:
```bash
# Continuous monitoring (runs every 5 seconds)
watch -n 5 '
echo "=== THREE NODE CONSENSUS STATUS ==="
echo ""
for i in 9944 9945 9946; do
  NAME=$([ $i -eq 9944 ] && echo "A" || ([ $i -eq 9945 ] && echo "B" || echo "C"))
  HEADER=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"chain_getHeader\",\"params\":[],\"id\":1}" \
    http://127.0.0.1:$i 2>/dev/null)
  NUM=$(echo $HEADER | jq -r ".result.number // \"offline\"")
  HASH=$(echo $HEADER | jq -r ".result.hash // \"\"" | cut -c1-18)
  PEERS=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"system_peers\",\"params\":[],\"id\":1}" \
    http://127.0.0.1:$i 2>/dev/null | jq -r ".result | length // 0")
  echo "Node $NAME (port $i): Block $NUM | Hash: ${HASH}... | Peers: $PEERS"
done
'
```

**Success Criteria**:
- [ ] All three nodes eventually show same block hash
- [ ] Each node shows 2 peers
- [ ] Block height increases over time
- [ ] Forks resolve (temporary hash differences converge)

**Cleanup**:
```bash
rm -rf /tmp/node-a /tmp/node-b /tmp/node-c
```

---

### 3.3 Network Partition & Recovery Test

**Purpose**: Verify the network handles partitions and reorganizes to the longest chain.

**Setup**: Start with 3-node setup from Test 3.2.

**Phase 1 - Establish Baseline** (2 minutes):
```bash
# Wait for all nodes to sync to same height
sleep 120

# Record baseline
echo "=== BASELINE (before partition) ==="
for port in 9944 9945 9946; do
  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    http://127.0.0.1:$port | jq -r '.result | "Port \($port): Block #\(.number)"'
done
```

**Phase 2 - Create Partition** (simulate by stopping Node B):
```bash
# In Terminal 2: Press Ctrl+C to stop Node B
# This creates partition: [A] <---> [C] but B is isolated
```

**Phase 3 - Let Chains Diverge** (2 minutes):
```bash
sleep 120

echo "=== DURING PARTITION ==="
echo "Node A:"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result'

echo "Node C:"
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
  http://127.0.0.1:9946 | jq '.result'

# Note: A and C should have same or similar height
# B is offline
```

**Phase 4 - Heal Partition** (restart Node B):
```bash
# Terminal 2: Restart Node B
HEGEMON_MINE=1 HEGEMON_MINE_THREADS=1 \
cargo run --release -p hegemon-node --features substrate -- \
  --dev --tmp --base-path /tmp/node-b \
  --rpc-port 9945 --port 30334 --name "NodeB" --require-pq \
  --bootnodes /ip4/127.0.0.1/tcp/30333
```

**Phase 5 - Verify Recovery** (1 minute):
```bash
sleep 60

echo "=== AFTER RECOVERY ==="
for port in 9944 9945 9946; do
  HEADER=$(curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    http://127.0.0.1:$port)
  echo "Port $port:"
  echo "  Block: $(echo $HEADER | jq -r '.result.number')"
  echo "  Hash:  $(echo $HEADER | jq -r '.result.hash')"
done
```

**Success Criteria**:
- [ ] After partition heals, all nodes converge to same block hash
- [ ] The converged chain is the longest chain
- [ ] Logs may show "Reorganization" or "Best block changed"

---

## Part 4: Environment Variables Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `HEGEMON_MINE` | `0` | Enable mining (`1` = enabled) |
| `HEGEMON_MINE_THREADS` | `1` | Number of mining threads |
| `HEGEMON_REQUIRE_PQ` | `true` | Require PQ-secure connections |
| `HEGEMON_PQ_VERBOSE` | `false` | Verbose PQ handshake logging |
| `HEGEMON_BLOCK_TIME_MS` | `10000` | Target block time in milliseconds |
| `PROPTEST_MAX_CASES` | `256` | Property test iterations |

---

## Part 5: Troubleshooting

### Node Won't Start

```bash
# Check if ports are in use
lsof -i :9944
lsof -i :30333

# Kill any hanging processes
pkill -f "hegemon-node"
pkill -f "substrate_node"

# Clean up temp directories
rm -rf /tmp/hegemon-* /tmp/node-*
```

### Nodes Won't Connect

```bash
# Verify PQ handshake is working
HEGEMON_PQ_VERBOSE=1 cargo run --release -p hegemon-node --features substrate -- \
  --dev --tmp --pq-verbose

# Check for firewall issues (macOS)
sudo pfctl -sr | grep "block"

# Try with hybrid mode (allows legacy fallback)
cargo run --release -p hegemon-node --features substrate -- \
  --dev --tmp --hybrid-pq
```

### No Blocks Being Mined

```bash
# Verify mining is enabled
echo $HEGEMON_MINE  # Should be "1"

# Check difficulty (dev chain should be low)
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_consensusStatus","params":[],"id":1}' \
  http://127.0.0.1:9944 | jq '.result.difficulty'

# Increase threads
HEGEMON_MINE_THREADS=4 cargo run ...
```

### RPC Not Responding

```bash
# Verify node is running
ps aux | grep hegemon

# Check RPC is bound
netstat -an | grep 9944

# Try localhost explicitly
curl http://127.0.0.1:9944 -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'
```

---

## Part 6: Test Results Template

Use this template to record test results:

```markdown
## Substrate Integration Test Results

**Date**: YYYY-MM-DD
**Tester**: [Name]
**Branch**: substrate
**Commit**: [short hash]

### Automated Tests

| Test Suite | Result | Duration | Notes |
|------------|--------|----------|-------|
| Unit Tests | ✅/❌ | Xm Xs | |
| Substrate Tests (9) | ✅/❌ | Xm Xs | |
| PQ Network Tests (19) | ✅/❌ | Xm Xs | |
| Security Pipeline | ✅/❌ | Xm Xs | |

### Manual Integration Tests

| Test | Result | Notes |
|------|--------|-------|
| Single Node Mining | ✅/❌ | Block height: X |
| Two Node Sync | ✅/❌ | Sync time: Xs |
| Three Node Consensus | ✅/❌ | Fork resolution: Y/N |
| Partition Recovery | ✅/❌ | Reorg observed: Y/N |

### Issues Found

1. [Issue description]
   - Severity: High/Medium/Low
   - Steps to reproduce: ...
   - Logs: ...

### Sign-off

- [ ] All automated tests pass
- [ ] Manual integration tests completed
- [ ] No critical issues found
- [ ] Ready for merge/release
```

---

## Part 7: CI Integration

The automated tests are integrated into CI via `.github/workflows/ci.yml`:

```yaml
substrate-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - name: Build with Substrate feature
      run: cargo build --release -p hegemon-node --features substrate
    - name: Run Substrate tests
      run: cargo test -p security-tests --test multi_node_substrate --features substrate
    - name: Run PQ network tests
      run: cargo test -p network
```

---

## Appendix: Quick Command Cheat Sheet

```bash
# === BUILD ===
cargo build --release -p hegemon-node --features substrate

# === AUTOMATED TESTS ===
cargo test -p security-tests --test multi_node_substrate --features substrate
cargo test -p network

# === SINGLE NODE ===
HEGEMON_MINE=1 cargo run --release -p hegemon-node --features substrate -- --dev --tmp

# === MULTI-NODE ===
# Node A: HEGEMON_MINE=1 ... --port 30333 --rpc-port 9944
# Node B: ... --port 30334 --rpc-port 9945 --bootnodes /ip4/127.0.0.1/tcp/30333

# === RPC QUERIES ===
# Block header
curl -s localhost:9944 -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}'

# Peer count
curl -s localhost:9944 -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}'

# Health
curl -s localhost:9944 -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}'

# === CLEANUP ===
pkill -f hegemon-node; rm -rf /tmp/hegemon-* /tmp/node-*
```
