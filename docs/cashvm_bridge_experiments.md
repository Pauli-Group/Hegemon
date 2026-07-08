# CashVM Bridge Object Experiments

This note records the first BCH/CashVM bridge-object experiment. It does not claim a production BCH covenant exists. It defines the objects a CashVM landing area would need if BCH contracts verify a native STARK/hash proof of the same Hegemon bridge light-client statement used by RISC Zero.

## Object Model

The Hegemon source side stays unchanged: outbound bridge actions are ordered into `BridgeMessageV1` records and committed under the Hegemon header `message_root`.

The CashVM adapter adds BCH-specific objects:

- `CashVmBridgeOutputV1`: a 548-byte SHA-256-friendly output derived from `BridgeCheckpointOutputV1` plus `BridgeMessageV1`. It includes the trusted-checkpoint digest accepted by the previous CashVM state, so a spend cannot advance from a self-selected Hegemon anchor.
- `CashVmBridgeStateV1`: a 128-byte singleton state commitment suitable for a 2026 CashToken NFT commitment.
- `CashVmProofEnvelopeV1`: a proof-system-neutral envelope with verifier script hash, PQ soundness claim, statement digest, and proof bytes.
- `CashVmProofChunkV1`: ordered proof chunks with chained accumulators for proof objects that do not fit one transaction.

`CashVmBridgeOutputV1` does not accept caller-selected mint bindings. It first applies the decoded `BridgeMintPayloadV1` admission policy used by the native bridge path: version, destination, nonce, nonzero recipient, nonzero amount, bounded amount, and non-native asset must all hold. Its destination token category is then `SHA256("hegemon.cashvm.asset-token-category-v1", bridge_instance_id, destination_chain_id, asset_id)`, and its recipient locking-bytecode hash is `SHA256("hegemon.cashvm.recipient-locking-bytecode-hash-v1", destination_chain_id, recipient_commitment)`. The spend model recomputes both values from the decoded payload and committed bridge policy before it updates replay or supply state. The default Rust model is fail-closed without an explicit `CashVmProofVerifier`; tests that exercise a positive state transition install a verifier fixture, and arbitrary proof bytes are rejected when that verifier rejects.

The state commitment stores digests and counters, not full checkpoint data:

```text
magic/version: 4 bytes
bridge_policy_hash: 32 bytes
accepted_checkpoint_digest: 32 bytes
replay_root: 32 bytes
minted_supply: 16 bytes
sequence: 8 bytes
min_pq_soundness_bits: 2 bytes
flags: 2 bytes
total: 128 bytes
```

The bridge-policy hash commits to `verifier_script_hash`, `expected_destination_chain_id`, `bridge_instance_id`, `min_pq_soundness_bits`, and `flags`. The spend model requires the decoded mint payload destination to equal the committed expected destination, requires the next state to preserve policy fields, and derives the token category with the committed bridge instance id.

Replay protection is modeled as a depth-128 sparse replay set keyed by `(source_chain_id, message_nonce)`. Each spend carries a sibling path that must recompute the previous replay root with an empty leaf and the next replay root with the consumed leaf under the same key. Duplicate successor-state spends fail because the previous root already contains the consumed leaf, while out-of-order exits remain spendable because replay state is a set rather than a monotonic nonce frontier.

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
  RISC Zero journal: bytes=436 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
  CashVM bridge output: bytes=548 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
  RISC Zero succinct envelope: bytes=224508 fits_standard_tx=false fits_unlocking=false fits_stack_element=false stack_elements_required=23 fragment_payload_bytes=90000 fragment_transactions_required=3
  RISC Zero composite envelope: bytes=492158 fits_standard_tx=false fits_unlocking=false fits_stack_element=false stack_elements_required=50 fragment_payload_bytes=90000 fragment_transactions_required=6
```

The important result is that the compact Hegemon long-range witness is not too large for a CashVM-style standard transaction model. The current RISC Zero receipt envelopes are too large for a clean single-transaction BCH verifier path. A production BCH bridge should target a CashVM-native STARK/hash proof format or a multi-step proof-fragment covenant.

## Validation

Run:

```bash
cargo test -p cashvm-bridge --lib
```

The tests check deterministic encoding, 128-byte state commitment size, proof chunk reassembly, current measured object sizes, fail-closed behavior without a verifier, valid covenant-state transition acceptance with an explicit verifier, out-of-order replay-set updates, verifier rejection of arbitrary proof bytes, and rejection for empty proofs, weak PQ soundness, wrong verifier script hash, statement mismatch, checkpoint mismatch, replay-root tampering, duplicate replay from a successor state, destination-policy mismatch, bridge-instance token-category mismatch, policy weakening, supply overflow, and message tampering.

## Operator Notes

This experiment does not change mining setup. For shared Hegemon mining environments, operators should still set:

```bash
HEGEMON_SEEDS="hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333"
```

All miners on the same network must share the same seed list to avoid partitions and forks. Mining hosts must keep NTP or chrony enabled because future-skewed PoW timestamps are rejected.
