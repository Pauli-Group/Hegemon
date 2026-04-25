# Hegemon-to-Hegemon Loopback Bridge Example

This is the Hegemon-to-Hegemon zk bridge shape. It exercises both bridge ends with two Hegemon nodes and a RISC Zero prover:

1. Source Hegemon node accepts an outbound bridge action.
2. Source miner commits the ordered `BridgeMessageV1` under `message_root`.
3. Relayer exports `hegemon_exportBridgeWitness` after at least one confirming source block.
4. RISC Zero proves the exported compact `HegemonLongRangeProofV1` inside the zkVM and emits `RiscZeroBridgeReceiptV1`.
5. Example code submits the RISC Zero receipt envelope as the proof receipt.
6. Destination Hegemon node accepts an inbound bridge action and later consumes the replay key when mined.

Hegemon remains pure PoW. The bridge receipt proves a light-client statement about Hegemon; it is not fork choice, not finality voting, and not a validator set.

## Local Run

Build the node first:

```bash
make setup
make node
```

Run a source node with mining:

```bash
HEGEMON_MINE=1 ./target/release/hegemon-node \
  --dev \
  --base-path /tmp/hegemon-loop-source \
  --rpc-methods unsafe \
  --rpc-port 9944 \
  --port 30333
```

Run a destination node with mining in another terminal:

```bash
HEGEMON_MINE=1 ./target/release/hegemon-node \
  --dev \
  --base-path /tmp/hegemon-loop-destination \
  --rpc-methods unsafe \
  --rpc-port 9955 \
  --port 30334
```

Build the RISC Zero method/prover crates once. If macOS lacks Apple Metal developer tools, use `RISC0_SKIP_BUILD_KERNELS=1` for the CPU prover path:

```bash
cargo install rzup --version 0.5.1
rzup install rust
cargo check --manifest-path zk/risc0-bridge/methods/Cargo.toml
RISC0_SKIP_BUILD_KERNELS=1 cargo check --manifest-path zk/risc0-bridge/prover/Cargo.toml
```

Export a bridge witness from the source after the outbound message has a confirming block, prove `canonical.long_range_proof` with `zk/risc0-bridge/prover`, then run the loopback example with the produced `RiscZeroBridgeReceiptV1` hex. If no block hash is supplied, `hegemon_exportBridgeWitness` scans backward up to 4096 blocks from the current canonical tip and selects the latest canonical block containing a bridge message, so relayers do not need to race the miner before the next empty block is produced. Pass the source block hash explicitly for older messages.

Destination Hegemon accepts the Hegemon-to-Hegemon RISC Zero bridge only when the inbound action uses the protocol-pinned `HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1`. This is an allowlist check, not a relayer-controlled verifier registration.

```bash
RISC0_SKIP_BUILD_KERNELS=1 cargo run \
  --manifest-path zk/risc0-bridge/prover/Cargo.toml \
  --bin prove_hegemon_bridge \
  -- --proof-file /tmp/hegemon-long-range-proof.hex

For fast local smoke tests, set `HEGEMON_RISC0_RECEIPT_KIND=composite`. Composite receipts are native STARK receipts and are accepted by Hegemon, but they are linear-size. The default `succinct` mode is the size target for production relayers.

cargo run -p hegemon-node --example hegemon_loopback_bridge -- \
  --source-rpc http://127.0.0.1:9944 \
  --destination-rpc http://127.0.0.1:9955 \
  --payload "hello from Hegemon source" \
  --risc0-receipt-hex 0x...
```

For shared mining or public testnet operation, set `HEGEMON_SEEDS="hegemon.pauli.group:30333"` on every miner unless the approved seed list has been deliberately rotated. Miners on the same network must share the same seed list to avoid partitions and forks. Keep NTP or chrony enabled on mining hosts because future-skewed PoW timestamps are rejected.

For this local loopback, the source and destination are intentionally separate test roles.

## Code Shape

Source side:

```rust
let outbound = OutboundBridgeArgsV1 {
    destination_chain_id: HEGEMON_CHAIN_ID_V1,
    app_family_id: FAMILY_BRIDGE,
    payload,
};

hegemon_submitAction({
    "family_id": FAMILY_BRIDGE,
    "action_id": ACTION_BRIDGE_OUTBOUND,
    "public_args": base64(outbound.encode()),
});
```

Relayer/prover side:

```rust
let witness = hegemon_exportBridgeWitness([]);
let compact_proof = witness["canonical"]["long_range_proof"];
let receipt = prove_hegemon_bridge(compact_proof);
```

Destination side:

```rust
let inbound = InboundBridgeArgsV1 {
    source_chain_id: message.source_chain_id,
    source_message_nonce: message.message_nonce,
    verifier_program_hash,
    proof_receipt,
    message,
};

hegemon_submitAction({
    "family_id": FAMILY_BRIDGE,
    "action_id": ACTION_BRIDGE_INBOUND,
    "public_args": base64(inbound.encode()),
});
```

The destination node rejects malformed payload hashes, wrong destination chain IDs, empty receipts, pending duplicates, and already-consumed replay keys.
