# Hegemon Testnet Deployment

This directory contains configuration and tools for deploying the Hegemon testnet.

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

### 3. Generate Chain Spec

```bash
# Generate human-readable spec
./target/release/hegemon-node build-spec \
    --chain=testnet \
    --disable-default-bootnode \
    > config/testnet/testnet-spec.json

# Generate raw spec (required for nodes)
./target/release/hegemon-node build-spec \
    --chain=config/testnet/testnet-spec.json \
    --raw \
    > config/testnet/testnet-raw.json
```

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
curl -s http://localhost:9944/health | jq

# Check block height
curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"chain_getHeader","params":[],"id":1}' \
    http://localhost:9944 | jq '.result.number'

# Check peer count
curl -s -X POST -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"system_peers","params":[],"id":1}' \
    http://localhost:9944 | jq '. | length'
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| boot1 | 9944 (RPC), 30333 (P2P), 9615 (Metrics) | Primary mining node |
| boot2 | 9945 (RPC), 30334 (P2P), 9616 (Metrics) | Secondary mining node |
| boot3 | 9946 (RPC), 30335 (P2P), 9617 (Metrics) | Full node (non-mining) |
| dashboard | 80 | Web UI |
| prometheus | 9090 | Metrics aggregation |
| grafana | 3000 | Metrics visualization |

## Monitoring

### Prometheus

Access at http://localhost:9090

Example queries:
- `substrate_block_height{status="best"}` - Current block height
- `substrate_sub_libp2p_peers_count` - Connected peers
- `process_resident_memory_bytes` - Memory usage

### Grafana

Access at http://localhost:3000 (admin/admin)

Pre-configured dashboards:
- Hegemon Testnet Overview

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
hegemon-node \
    --dev \
    --chain=config/testnet/testnet-raw.json \
    --base-path=/data/hegemon \
    --port=30333 \
    --rpc-port=9944 \
    --bootnodes=/dns4/boot1.testnet.hegemon.network/tcp/30333/p2p/$BOOT1_PEER_ID \
    --name=my-node
```

## Connecting Wallet

```bash
# Sync wallet with testnet
wallet substrate-sync --endpoint ws://localhost:9944

# Start continuous sync daemon
wallet substrate-daemon --endpoint ws://localhost:9944
```

## Troubleshooting

### Node won't start

Check logs:
```bash
docker logs hegemon-boot1
```

Common issues:
- Missing chain spec: Ensure `config/testnet/testnet-raw.json` exists
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
- PQ transport is required (`--require-pq`)

## File Structure

```
config/
├── testnet/
│   ├── testnet-spec.json      # Human-readable chain spec
│   └── testnet-raw.json       # Raw chain spec (for nodes)
└── monitoring/
    ├── prometheus.yml         # Prometheus config
    └── grafana/
        ├── provisioning/
        │   ├── dashboards/    # Dashboard provisioning
        │   └── datasources/   # Datasource provisioning
        └── dashboards/        # Dashboard JSON files

keys/
├── boot1.key                  # Boot node 1 identity
├── boot2.key                  # Boot node 2 identity
└── boot3.key                  # Boot node 3 identity
```
