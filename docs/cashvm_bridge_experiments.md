# CashVM Bridge Object Experiments

This note records the first BCH/CashVM bridge-object experiment. It does not claim a production BCH covenant exists. It defines the objects a CashVM landing area would need if BCH contracts verify a native STARK/hash proof of the same Hegemon bridge light-client statement used by RISC Zero.

## Object Model

The Hegemon source side stays unchanged: outbound bridge actions are ordered into `BridgeMessageV1` records and committed under the Hegemon header `message_root`.

The CashVM adapter adds BCH-specific objects:

- `CashVmBridgeOutputV1`: a 516-byte SHA-256-friendly output derived from `BridgeCheckpointOutputV1` plus `BridgeMessageV1`.
- `CashVmBridgeStateV1`: a 128-byte singleton state commitment suitable for a 2026 CashToken NFT commitment.
- `CashVmProofEnvelopeV1`: a proof-system-neutral envelope with verifier script hash, PQ soundness claim, statement digest, and proof bytes.
- `CashVmProofChunkV1`: ordered proof chunks with chained accumulators for proof objects that do not fit one transaction.

The state commitment stores digests and counters, not full checkpoint data:

```text
magic/version: 4 bytes
verifier_script_hash: 32 bytes
accepted_checkpoint_digest: 32 bytes
replay_root: 32 bytes
minted_supply: 16 bytes
sequence: 8 bytes
min_pq_soundness_bits: 2 bytes
flags: 2 bytes
total: 128 bytes
```

Replay protection is modeled as an append-only hash root over `(source_chain_id, message_nonce)`. A production covenant can replace that with a more sophisticated sparse root if it needs parallel exits or absence proofs.

## Current Measurements

Run:

```bash
cargo run -p cashvm-bridge --bin cashvm_bridge_report
```

Current output:

```text
cashvm_limits:
  max_standard_tx_bytes=100000
  max_bytecode_bytes=10000
  max_stack_element_bytes=10000
  token_commitment_bytes_2026=128
  hegemon_cashvm_state_commitment_bytes=128
objects:
  HegemonLongRangeProofV1: bytes=9951 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
  RISC Zero journal: bytes=404 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
  CashVM bridge output: bytes=516 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
  RISC Zero succinct envelope: bytes=224508 fits_standard_tx=false fits_unlocking=false fits_stack_element=false stack_elements_required=23 fragment_payload_bytes=90000 fragment_transactions_required=3
  RISC Zero composite envelope: bytes=492158 fits_standard_tx=false fits_unlocking=false fits_stack_element=false stack_elements_required=50 fragment_payload_bytes=90000 fragment_transactions_required=6
```

The important result is that the compact Hegemon long-range witness is not too large for a CashVM-style standard transaction model. The current RISC Zero receipt envelopes are too large for a clean single-transaction BCH verifier path. A production BCH bridge should target a CashVM-native STARK/hash proof format or a multi-step proof-fragment covenant.

## Validation

Run:

```bash
cargo test -p cashvm-bridge --lib
```

The tests check deterministic encoding, 128-byte state commitment size, proof chunk reassembly, current measured object sizes, valid covenant-state transition acceptance, and rejection for empty proofs, weak PQ soundness, wrong verifier script hash, statement mismatch, checkpoint mismatch, replay-root tampering, policy weakening, supply overflow, and message tampering.

## Operator Notes

This experiment does not change mining setup. For shared Hegemon mining environments, operators should still set:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:30333"
```

All miners on the same network must share the same seed list to avoid partitions and forks. Mining hosts must keep NTP or chrony enabled because future-skewed PoW timestamps are rejected.
