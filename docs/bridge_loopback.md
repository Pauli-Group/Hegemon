# Hegemon-to-Hegemon Loopback Bridge Example

This is the Hegemon-to-Hegemon zk bridge shape. It exercises outbound witness export and the offline RISC Zero prover. Release native nodes currently reject inbound RISC Zero receipts because the standard `risc0-zkvm` verifier dependency graph links Groth16/BN254 code into the node binary.

1. Source Hegemon node accepts an outbound bridge action.
2. Source miner commits the ordered `BridgeMessageV1` under `message_root`.
3. Relayer exports `hegemon_exportBridgeWitness` after at least one confirming source block.
4. RISC Zero proves the exported compact `HegemonLongRangeProofV1` inside the zkVM and emits `RiscZeroBridgeReceiptV1`.
5. Example code can submit the RISC Zero receipt envelope as the proof receipt.
6. Destination Hegemon validates message-binding preconditions, then rejects staging until a PQ-clean verifier is integrated.

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

Export a bridge witness from the source after the outbound message has a confirming block, then prove `canonical.long_range_proof` with `zk/risc0-bridge/prover` to measure the offline RISC Zero envelope. If no block hash is supplied, `hegemon_exportBridgeWitness` scans backward up to 4096 blocks from the current canonical tip and selects the latest canonical block containing a bridge message, so relayers do not need to race the miner before the next empty block is produced. Pass the source block hash explicitly for older messages.

The inbound action still uses the protocol-pinned `HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1`, but release Hegemon rejects RISC Zero receipt staging after syntactic envelope/journal decoding. The fail-closed release decision table is covered by the Lean `Risc0ReleaseVerifier` formal-core vectors. Do not treat this document as an enabled bridge runbook until the destination verifier no longer pulls classical SNARK/curve code into `hegemon-node`.

```bash
RISC0_SKIP_BUILD_KERNELS=1 cargo run --release \
  --manifest-path zk/risc0-bridge/prover/Cargo.toml \
  --bin prove_hegemon_bridge \
  -- --proof-file /tmp/hegemon-long-range-proof.hex
```

For fast local prover measurements, set `HEGEMON_RISC0_RECEIPT_KIND=composite`. Composite receipts are native STARK receipts but are not accepted by the release Hegemon node while the RISC Zero verifier is disabled. The default `succinct` mode remains the size target for future relayers.

Use the profiler before proving when changing the light-client statement:

```bash
RISC0_SKIP_BUILD_KERNELS=1 cargo run \
  --manifest-path zk/risc0-bridge/prover/Cargo.toml \
  --bin profile_hegemon_bridge \
  -- --proof-file /tmp/hegemon-long-range-proof.hex
```

On `hegemon-dev`, a 9951-byte live long-range proof currently executes in 962524 RISC Zero guest cycles. Cached release proving measured 8m37s for a 492158-byte composite receipt envelope and 10m46s for a 224508-byte succinct receipt envelope. These remain offline measurements; do not use Groth16/KZG wrapping or any verifier stack that links classical curve/SNARK code into the PQ bridge path.

```bash
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

Destination side (currently rejected by release nodes after prechecks):

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

The destination node rejects malformed payload hashes, wrong destination chain IDs, empty receipts, pending duplicates, and already-consumed replay keys. With the current PQ-only release build it also rejects syntactically valid RISC Zero receipts before staging any pending action.
