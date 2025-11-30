# Miner + wallet quickstart (Substrate node)

Use this runbook to stand up mining nodes and verify they are producing blocks with the Substrate-based `hegemon-node` binary.

## 1. Prerequisites

- Run `make setup` on a fresh clone to install toolchains and baseline dependencies.
- Build the binary:
  ```bash
  make node
  ```

## 2. Start a mining node

```bash
HEGEMON_MINE=1 ./target/release/hegemon-node --dev \
  --base-path /tmp/node-a \
  --port 30333 \
  --rpc-port 9944
```

The `--dev` flag pre-funds test accounts and enables fast block times.

## 3. Verify the node is running

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_health"}' \
  http://127.0.0.1:9944
```

Check block production:
```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "chain_getHeader"}' \
  http://127.0.0.1:9944
```

## 4. Start a second node

In another terminal, start a second node that peers with the first:

```bash
./target/release/hegemon-node --dev \
  --base-path /tmp/node-b \
  --port 30334 \
  --rpc-port 9945 \
  --bootnodes /ip4/127.0.0.1/tcp/30333
```

## 5. Verify peer connectivity

```bash
curl -s -H "Content-Type: application/json" \
  -d '{"id":1, "jsonrpc":"2.0", "method": "system_peers"}' \
  http://127.0.0.1:9944
```

Both nodes should see each other as peers and sync blocks.
