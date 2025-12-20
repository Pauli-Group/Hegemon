# Mainnet Launch Checklist & Runbook

**Phase 15.3.3 - Production Hardening**

This document provides the pre-launch verification checklist and day-of-launch runbook for Hegemon mainnet deployment.

---

## Table of Contents

1. [Pre-Launch Checklist](#pre-launch-checklist)
2. [Launch Timeline](#launch-timeline)
3. [Day-of-Launch Runbook](#day-of-launch-runbook)
4. [Post-Launch Verification](#post-launch-verification)
5. [Rollback Procedure](#rollback-procedure)
6. [Emergency Contacts](#emergency-contacts)

---

## Pre-Launch Checklist

### 🔐 Security Audit (T-30 days)

- [ ] **External Security Audit Complete**
  - Audit firm: _________________
  - Report date: _________________
  - Critical findings resolved: Yes / No
  - All findings documented in SECURITY_REVIEWS.md

- [ ] **PQ Parameters Verified by Cryptographer**
  - ML-KEM-768: FIPS 203 compliant
  - ML-DSA-65: FIPS 204 compliant
  - FRI parameters: 128-bit security
  - Reviewer: _________________

- [ ] **ECC Audit Script Passes**
  ```bash
  ./scripts/security-audit.sh
  # Must exit with code 0
  ```

- [ ] **No Known Vulnerabilities**
  - CVE check: `./scripts/dependency-audit.sh`
  - Dependency review completed
  - No critical/high severity issues

### ✅ Testing Complete (T-14 days)

- [ ] **All Unit Tests Pass**
  ```bash
  cargo test --workspace
  # Expected: 400+ tests pass
  ```

- [ ] **All Integration Tests Pass**
  ```bash
  cargo test --workspace -- --ignored
  # Run against live node
  ```

- [ ] **Testnet Running 7+ Days**
  - Start date: _________________
  - Blocks mined: _________________
  - No consensus failures
  - No state corruption

- [ ] **3+ Boot Nodes Syncing**
  - Boot node 1: _________________
  - Boot node 2: _________________
  - Boot node 3: _________________
  - All at same block height

- [ ] **Shielded Transactions Verified**
  - Shield transaction: TX hash _________________
  - Unshield transaction: TX hash _________________
  - Transfer transaction: TX hash _________________

### 📊 Performance Verified (T-7 days)

- [ ] **STARK Prove Time**
  - Target: < 10 seconds
  - Actual: _________________ seconds
  ```bash
  cargo run -p circuits-bench --release -- --iterations 10
  ```

- [ ] **STARK Verify Time**
  - Target: < 200 ms
  - Actual: _________________ ms

- [ ] **Note Scan Time**
  - Target: < 1 second per 1000 notes
  - Actual: _________________ ms
  ```bash
  cargo run -p wallet-bench --release -- --scanning --scan-notes 1000
  ```

- [ ] **Block Time Stable**
  - Target: ~60 seconds
  - Testnet average: _________________

### 🖥️ Infrastructure Ready (T-3 days)

- [ ] **Boot Nodes Deployed**
  | Node | Region | IP/DNS | Status |
  |------|--------|--------|--------|
  | boot1 | _______ | _______ | ✅ Ready |
  | boot2 | _______ | _______ | ✅ Ready |
  | boot3 | _______ | _______ | ✅ Ready |

- [ ] **Monitoring Configured**
  - Prometheus: URL _________________
  - Grafana: URL _________________
  - Alerting: PagerDuty / Slack / ___

- [ ] **Telemetry Endpoint Operational**
  - URL: wss://telemetry.hegemon.network/submit/
  - Test connection successful

- [ ] **Block Explorer Ready**
  - URL: _________________
  - Genesis block displays correctly

### 📚 Documentation Published (T-1 day)

- [ ] **User Guide Available**
  - URL: _________________

- [ ] **Wallet Download Available**
  - Version: _________________
  - Checksums published

- [ ] **Mining Guide Available**
  - Solo mining instructions
  - Pool mining (if applicable)

- [ ] **Security Documentation Public**
  - THREAT_MODEL.md published
  - SECURITY_REVIEWS.md published
  - Responsible disclosure policy

---

## Launch Timeline

### T-24 Hours

| Time | Action | Owner | Status |
|------|--------|-------|--------|
| T-24h | Final testnet checkpoint | DevOps | ⬜ |
| T-24h | Verify all boot nodes synced | DevOps | ⬜ |
| T-24h | Run security audit script | Security | ⬜ |
| T-24h | Freeze mainnet binary | Release | ⬜ |
| T-24h | Prepare announcement | Marketing | ⬜ |

### T-6 Hours

| Time | Action | Owner | Status |
|------|--------|-------|--------|
| T-6h | Clear testnet (if reusing infra) | DevOps | ⬜ |
| T-6h | Deploy mainnet genesis | DevOps | ⬜ |
| T-6h | Verify genesis block hash | All | ⬜ |
| T-6h | Final boot node config check | DevOps | ⬜ |

### T-1 Hour

| Time | Action | Owner | Status |
|------|--------|-------|--------|
| T-1h | Start boot nodes (listen-only) | DevOps | ⬜ |
| T-1h | Verify boot node connectivity | DevOps | ⬜ |
| T-1h | Enable Prometheus monitoring | DevOps | ⬜ |
| T-1h | Final team sync call | All | ⬜ |

### T-0 (Launch)

| Time | Action | Owner | Status |
|------|--------|-------|--------|
| T-0 | Enable P2P connections | DevOps | ⬜ |
| T-0 | Announce launch | Marketing | ⬜ |
| T-0 | Monitor first blocks | DevOps | ⬜ |
| T-0 | Verify first block mined | DevOps | ⬜ |

### T+1 Hour

| Time | Action | Owner | Status |
|------|--------|-------|--------|
| T+1h | Verify first shielded TX | Testing | ⬜ |
| T+1h | Check peer count growth | DevOps | ⬜ |
| T+1h | Monitor block propagation | DevOps | ⬜ |
| T+1h | Check for error spikes | DevOps | ⬜ |

### T+24 Hours

| Time | Action | Owner | Status |
|------|--------|-------|--------|
| T+24h | Post-launch stability review | All | ⬜ |
| T+24h | Document any issues | DevOps | ⬜ |
| T+24h | Publish launch report | Marketing | ⬜ |

---

## Day-of-Launch Runbook

### Phase 1: Pre-Launch Verification (T-1h to T-0)

```bash
# 1. Verify all boot nodes are at genesis
for node in boot1 boot2 boot3; do
    echo "Checking $node..."
    ssh $node "hegemon-node key inspect-node-key /etc/hegemon/node-key.pem"
    ssh $node "systemctl status hegemon-bootnode"
done

# 2. Verify genesis block hash matches
EXPECTED_GENESIS="0x..." # Fill in
for node in boot1 boot2 boot3; do
    ACTUAL=$(ssh $node "curl -s localhost:9933 -X POST -H 'Content-Type: application/json' \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlockHash\",\"params\":[0],\"id\":1}' | jq -r .result")
    if [ "$ACTUAL" != "$EXPECTED_GENESIS" ]; then
        echo "ERROR: Genesis mismatch on $node!"
        exit 1
    fi
done
echo "Genesis verified on all boot nodes"

# 3. Run security audit
./scripts/security-audit.sh
./scripts/verify-no-legacy-production.sh

# 4. Check Prometheus
curl -s http://prometheus:9090/-/healthy
```

### Phase 2: Launch (T-0)

```bash
# 1. Enable P2P on all boot nodes
for node in boot1 boot2 boot3; do
    ssh $node "systemctl restart hegemon-bootnode"
done

# 2. Verify nodes are accepting connections
sleep 30
for node in boot1 boot2 boot3; do
    PEERS=$(ssh $node "curl -s localhost:9933 -X POST -H 'Content-Type: application/json' \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"system_health\",\"params\":[],\"id\":1}' | jq .result.peers")
    echo "$node: $PEERS peers"
done

# 3. Monitor first block
watch -n 5 'curl -s http://boot1:9933 -X POST -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"chain_getHeader\",\"params\":[],\"id\":1}" | jq .result.number'
```

### Phase 3: Post-Launch Verification (T+1h)

```bash
# 1. Check block height across nodes
for node in boot1 boot2 boot3; do
    HEIGHT=$(ssh $node "curl -s localhost:9933 -X POST -H 'Content-Type: application/json' \
        -d '{\"jsonrpc\":\"2.0\",\"method\":\"chain_getHeader\",\"params\":[],\"id\":1}' | jq -r '.result.number'")
    echo "$node: Block $HEIGHT"
done

# 2. Submit test shielded transaction
./scripts/submit-test-shielded-tx.sh

# 3. Verify transaction inclusion
TX_HASH="0x..."  # From previous step
curl -s http://boot1:9933 -X POST -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"chain_getBlock\",\"params\":[],\"id\":1}" | jq

# 4. Check error rates
curl -s http://prometheus:9090/api/v1/query?query=rate(hegemon_errors_total[5m])
```

---

## Post-Launch Verification

### Block Production

```bash
# Verify blocks being produced at target rate
# Target: ~1 block per minute (60s block time)

START_BLOCK=$(curl -s http://boot1:9933 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' | jq -r '.result.number' | xargs printf "%d\n")

sleep 300  # Wait 5 minutes

END_BLOCK=$(curl -s http://boot1:9933 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' | jq -r '.result.number' | xargs printf "%d\n")

BLOCKS=$((END_BLOCK - START_BLOCK))
echo "Blocks in 5 min: $BLOCKS (expected: ~5)"
```

### Network Health

```bash
# Check peer count growing
curl -s http://boot1:9933 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' | jq

# Expected: peers > 10 within first hour
```

### Shielded Pool

```bash
# Verify shielded pool state
curl -s http://boot1:9933 -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"shieldedPool_getCommitmentCount","params":[],"id":1}' | jq
```

---

## Rollback Procedure

### If Critical Issue Detected

1. **Immediately notify all boot node operators**
   ```bash
   # Stop all boot nodes
   for node in boot1 boot2 boot3; do
       ssh $node "systemctl stop hegemon-bootnode"
   done
   ```

2. **Announce network pause**
   - Twitter/Discord: "Hegemon mainnet paused for emergency maintenance"

3. **Assess the issue**
   - Collect logs from all boot nodes
   - Identify root cause

4. **Decision point:**
   - If fix is simple: Apply patch, restart
   - If state corruption: Roll back to genesis
   - If fundamental issue: Postpone launch

5. **Rollback to genesis (if needed)**
   ```bash
   for node in boot1 boot2 boot3; do
       ssh $node "rm -rf /var/lib/hegemon/*"
       ssh $node "systemctl start hegemon-bootnode"
   done
   ```

---

## Emergency Contacts

| Role | Name | Contact |
|------|------|---------|
| Lead Developer | _______ | _______ |
| DevOps Lead | _______ | _______ |
| Security Lead | _______ | _______ |
| Comms Lead | _______ | _______ |

### Escalation Path

1. **P1 (Critical)**: Consensus failure, state corruption
   - Notify all contacts immediately
   - Stop network if needed

2. **P2 (High)**: Performance degradation, high error rate
   - Notify DevOps and Lead Developer
   - Monitor closely

3. **P3 (Medium)**: Minor issues, cosmetic bugs
   - Document and fix in next release

---

## Sign-Off

| Checkpoint | Verified By | Date |
|------------|-------------|------|
| Security Audit Complete | _______ | _______ |
| Testing Complete | _______ | _______ |
| Infrastructure Ready | _______ | _______ |
| Documentation Published | _______ | _______ |
| **LAUNCH APPROVED** | _______ | _______ |

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-30  
**Phase**: 15.3.3 Production Hardening
