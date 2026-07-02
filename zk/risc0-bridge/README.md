# Hegemon RISC Zero Bridge

This directory contains the RISC Zero transport for Hegemon bridge proofs.

`methods/` builds the zkVM guest method named `hegemon_bridge`. The guest reads SCALE-encoded `HegemonLongRangeProofV1`, runs `consensus-light-client::verify_hegemon_long_range_proof`, and commits SCALE-encoded `BridgeCheckpointOutputV1` to the journal.

`prover/` wraps that method for hosts. `prove_hegemon_bridge` returns `RiscZeroBridgeReceiptV1`, which is the object accepted by destination Hegemon inbound bridge actions.

Build checks:

```bash
cargo install rzup --version 0.5.1
rzup install rust
cargo check --manifest-path zk/risc0-bridge/methods/Cargo.toml
RISC0_SKIP_BUILD_KERNELS=1 cargo check --manifest-path zk/risc0-bridge/prover/Cargo.toml
```

The second command uses the CPU prover path on macOS hosts without Apple Metal developer tools.

To prove an exported `canonical.long_range_proof`:

```bash
RISC0_SKIP_BUILD_KERNELS=1 cargo run \
  --manifest-path zk/risc0-bridge/prover/Cargo.toml \
  --bin prove_hegemon_bridge \
  -- 0x...compact-long-range-proof...
```
