#!/usr/bin/env bash
set -euo pipefail

# Generate deterministic native-node seed material for local testnet boot nodes.

KEYS_DIR="${KEYS_DIR:-./keys}"
NODE_COUNT="${NODE_COUNT:-3}"
APPROVED_SEEDS="${HEGEMON_SEEDS:-hegemon.pauli.group:30333}"

mkdir -p "$KEYS_DIR"

echo "Generating native Hegemon testnet seeds"
echo "Approved HEGEMON_SEEDS=$APPROVED_SEEDS"
echo

for i in $(seq 1 "$NODE_COUNT"); do
    seed_file="${KEYS_DIR}/boot${i}.seed"
    if [ ! -f "$seed_file" ]; then
        openssl rand -hex 32 >"$seed_file"
        chmod 600 "$seed_file"
    fi
    peer_id="$(sha256sum "$seed_file" | awk '{print substr($1, 1, 64)}')"
    echo "boot${i}: seed_file=$seed_file native_peer_hint=$peer_id"
done

cat >.env.testnet <<EOF
# Hegemon native testnet configuration
# Generated: $(date)
HEGEMON_SEEDS=${APPROVED_SEEDS}
HEGEMON_MAX_PEERS=64
EOF

echo
echo "Configuration written to .env.testnet"
echo "Keep NTP or chrony enabled on miners; future-skewed PoW timestamps are rejected."
