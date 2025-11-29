#!/bin/bash
# Single Node Smoke Test for Task 11.8.1
# Run this AFTER starting the node manually in another terminal with:
#   HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp
#
# This script assumes the node is already running on port 9944

RPC_URL="http://127.0.0.1:9944"

echo "=== Task 11.8.1: Single Node Smoke Test ==="
echo "Assumes node is running at $RPC_URL"
echo ""

# Test 1: Check blocks are being mined
echo "Test 1: Checking if blocks are being mined..."
HEADER_RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
  "$RPC_URL")

BLOCK_HEX=$(echo "$HEADER_RESULT" | grep -o '"number":"[^"]*"' | cut -d'"' -f4)
if [ -z "$BLOCK_HEX" ]; then
  echo "❌ FAIL: Could not get block number. Is the node running?"
  echo "Response: $HEADER_RESULT"
  exit 1
fi
# Convert hex to decimal
BLOCK_NUM=$((BLOCK_HEX))
echo "Current block: $BLOCK_NUM"
if [ "$BLOCK_NUM" -gt 0 ]; then
  echo "✅ PASS: Blocks being mined"
else
  echo "❌ FAIL: No blocks mined yet"
  exit 1
fi
echo ""

# Test 2: Verify state storage works
echo "Test 2: Checking state storage (Alice's balance)..."
STORAGE_RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"state_getStorage","params":["0x26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9de1e86a9a8c739864cf3cc5ec2bea59fd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"],"id":1}' \
  "$RPC_URL")

BALANCE=$(echo "$STORAGE_RESULT" | grep -o '"result":"[^"]*"' | cut -d'"' -f4)
if [ -z "$BALANCE" ] || [ "$BALANCE" = "null" ]; then
  echo "❌ FAIL: Cannot read storage"
  echo "Response: $STORAGE_RESULT"
  exit 1
fi
echo "Alice's balance data: ${BALANCE:0:40}..."
echo "✅ PASS: State storage readable"
echo ""

# Test 3: Verify transaction pool RPC works
echo "Test 3: Checking transaction pool RPC..."
PENDING_RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"author_pendingExtrinsics","params":[],"id":1}' \
  "$RPC_URL")

if echo "$PENDING_RESULT" | grep -q '"result"'; then
  echo "Response: $PENDING_RESULT"
  echo "✅ PASS: Transaction pool RPC works"
else
  echo "❌ FAIL: Transaction pool RPC failed"
  echo "Response: $PENDING_RESULT"
  exit 1
fi
echo ""

# Test 4: Verify consensus RPC works
echo "Test 4: Checking consensus RPC (hegemon_consensusStatus)..."
CONSENSUS_RESULT=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"hegemon_consensusStatus","params":[],"id":1}' \
  "$RPC_URL")

if echo "$CONSENSUS_RESULT" | grep -q '"result"'; then
  echo "Response: $CONSENSUS_RESULT"
  echo "✅ PASS: Consensus RPC works"
else
  echo "⚠️  WARN: Consensus RPC may not be implemented yet"
  echo "Response: $CONSENSUS_RESULT"
fi
echo ""

echo "=== ALL SINGLE NODE TESTS COMPLETED ==="
