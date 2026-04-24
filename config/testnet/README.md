# Hegemon Testnet Deployment

This directory contains configuration and tools for deploying the Hegemon testnet.

For the fresh-testnet rollout on the laptop + `hegemon-ovh`,
follow [config/testnet-initialization.md](/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet-initialization.md)
before starting any host. The laptop-created boot-wallet address is the payout
address that should be configured everywhere for mining.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Rust toolchain (for building from source)
- jq (for scripts)

### 1. Build the Node Image

```bash
# From project root
docker build -t hegemon/node:latest .
```

### 2. Generate Node Keys

```bash
./scripts/generate-testnet-keys.sh
```

This creates:
- `keys/boot1.key`, `keys/boot2.key`, `keys/boot3.key` - Node identity keys
- `.env.testnet` - Environment file with peer IDs

All miners should use the same approved `HEGEMON_SEEDS` list when joining the shared testnet. Divergent seed lists can reduce connectivity and increase fork risk. Enable NTP/chrony on every host because PoW timestamps are rejected if they exceed the future-skew bound.

### 3. Build The Native Node

```bash
make node
```

The native testnet starts from native genesis state and does not use chain-spec generation.

### 4. Start the Testnet

```bash
# Load environment variables
source .env.testnet

# Start all services
docker-compose -f docker-compose.testnet.yml up -d
```

### 5. Verify Deployment

```bash
# Check node health
curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' \
    http://localhost:9944 | jq '.result'

# Check block height
curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    http://localhost:9944 | jq '.result.number'

# Check peer count
curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' \
    http://localhost:9944 | jq '.result.peers'
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| boot1 | 9944 (RPC), 30333 (P2P) | Primary mining node |
| boot2 | 9945 (RPC), 30334 (P2P) | Secondary mining node |
| boot3 | 9946 (RPC), 30335 (P2P) | Full node (non-mining) |

## Monitoring

Use JSON-RPC for current native testnet checks:

```bash
curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    http://localhost:9944 | jq '.result.number'

curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"system_health","params":[],"id":1}' \
    http://localhost:9944 | jq '.result.peers'
```

## Soak Testing

Run a long-duration stability test:

```bash
# 7-day soak test
./scripts/soak-test.sh 168

# 24-hour test
./scripts/soak-test.sh 24

# Custom RPC endpoint
RPC_ENDPOINT=http://testnet.example.com:9944 ./scripts/soak-test.sh 168
```

The soak test monitors:
- Block production rate
- Peer connectivity
- Memory usage
- Chain forks

## Connecting External Nodes

To connect an external node to the testnet:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:30333" \
hegemon-node \
    --dev \
    --base-path=/data/hegemon \
    --port=30333 \
    --rpc-port=9944 \
    --name=my-node
```

## Connecting Wallet

```bash
# Sync wallet with testnet
wallet node-sync --ws-url ws://localhost:9944

# Start continuous sync daemon
wallet node-daemon --ws-url ws://localhost:9944
```

## Troubleshooting

### Node won't start

Check logs:
```bash
docker logs hegemon-boot1
```

Common issues:
- Missing keys: Run `./scripts/generate-testnet-keys.sh`
- Port conflict: Check if ports 9944, 30333 are in use

### Nodes not connecting

1. Verify peer IDs are correctly set in `.env.testnet`
2. Check network connectivity between containers
3. Verify boot node is healthy before dependent nodes start

### No blocks being produced

1. Check mining is enabled: `HEGEMON_MINE=1`
2. Verify difficulty is appropriate for testnet
3. Check node logs for mining errors

### High memory usage

1. Check for memory leaks with soak test
2. Increase container memory limits
3. Consider pruning chain data

## Security Notes

- Testnet keys in this directory are for testing only
- Do not use testnet keys on mainnet
- RPC is exposed with `--rpc-methods=safe` by default
- PQ transport is the default transport; no extra flag is required

## File Structure

```
config/
└── testnet/
    └── README.md             # Native testnet deployment guide

keys/
├── boot1.key                  # Boot node 1 identity
├── boot2.key                  # Boot node 2 identity
└── boot3.key                  # Boot node 3 identity
```
