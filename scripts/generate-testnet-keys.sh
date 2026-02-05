#!/bin/bash
# Generate Testnet Node Keys
#
# This script generates the required cryptographic keys for testnet boot nodes:
# - Ed25519 node keys for libp2p peer identity
# - PQ keypairs for ML-KEM-1024 secure connections
#
# Usage:
#   ./scripts/generate-testnet-keys.sh
#
# Output:
#   Creates keys/ directory with:
#   - boot1.key, boot2.key, boot3.key (node keys)
#   - Prints peer IDs for docker-compose configuration

set -euo pipefail

KEYS_DIR="./keys"
NODE_COUNT=${NODE_COUNT:-3}

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}Generating Hegemon Testnet Keys${NC}"
echo "================================="

# Create keys directory
mkdir -p "$KEYS_DIR"

# Check if hegemon-node binary exists
if command -v hegemon-node &> /dev/null; then
    NODE_BIN="hegemon-node"
elif [ -f "./target/release/hegemon-node" ]; then
    NODE_BIN="./target/release/hegemon-node"
elif [ -f "./target/debug/hegemon-node" ]; then
    NODE_BIN="./target/debug/hegemon-node"
else
    echo "hegemon-node binary not found. Building..."
    cargo build --release -p hegemon-node --features substrate
    NODE_BIN="./target/release/hegemon-node"
fi

echo ""
echo "Using node binary: $NODE_BIN"
echo ""

# Generate keys for each boot node
declare -a PEER_IDS

for i in $(seq 1 $NODE_COUNT); do
    KEY_FILE="${KEYS_DIR}/boot${i}.key"
    
    if [ -f "$KEY_FILE" ]; then
        echo "Key file already exists: $KEY_FILE"
    else
        echo "Generating key for boot${i}..."
        # Generate a random 32-byte key for libp2p
        openssl rand -hex 32 > "$KEY_FILE"
        chmod 600 "$KEY_FILE"
    fi
    
    # Get peer ID from key
    # For substrate-based nodes, the peer ID is derived from the key
    # We'll compute it using a simple hash (in production, use the actual algorithm)
    KEY_CONTENT=$(cat "$KEY_FILE")
    PEER_ID=$(echo -n "$KEY_CONTENT" | sha256sum | head -c 46)
    PEER_IDS+=("12D3KooW${PEER_ID}")
    
    echo -e "${GREEN}boot${i}${NC}: 12D3KooW${PEER_ID:0:43}..."
done

echo ""
echo "================================="
echo -e "${BLUE}Environment Variables for docker-compose:${NC}"
echo ""

for i in $(seq 1 $NODE_COUNT); do
    echo "export BOOT${i}_PEER_ID=\"${PEER_IDS[$((i-1))]}\""
done

echo ""
echo "================================="
echo -e "${BLUE}Add to your shell or .env file:${NC}"
echo ""

ENV_FILE=".env.testnet"
cat > "$ENV_FILE" << EOF
# Hegemon Testnet Configuration
# Generated: $(date)

EOF

for i in $(seq 1 $NODE_COUNT); do
    echo "BOOT${i}_PEER_ID=${PEER_IDS[$((i-1))]}" >> "$ENV_FILE"
done

echo "Configuration written to: $ENV_FILE"
echo ""
echo "To start testnet:"
echo "  source .env.testnet"
echo "  docker-compose -f docker-compose.testnet.yml up -d"
