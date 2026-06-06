# Hegemon Lean Formal Core

This directory contains the machine-checked Lean 4 layer for Hegemon's production-critical validity rules.

The project is pinned by `lean-toolchain` and builds with:

```bash
bash ../../scripts/check_lean_formal.sh
```

Current proved kernel:

- `Hegemon/Bytes.lean` defines shared executable byte, endian, hex, and deterministic patterned-byte helpers used by generated Lean conformance vectors.
- `Hegemon.Bridge.accept_prevents_duplicate` in `Hegemon/Bridge/Replay.lean` proves that once the executable inbound replay-state transition accepts a replay key and returns a next state, the same key cannot be accepted again from that next state.
- `Hegemon.Bridge.stage_prevents_duplicate_pending`, `Hegemon.Bridge.import_prevents_reimport`, and `Hegemon.Bridge.import_prevents_restaging` prove the two-phase inbound replay behavior used by the native bridge path: a staged key cannot be staged twice, and an imported key cannot be imported or staged again.
- `Hegemon/Bridge/Encoding.lean` defines the executable bridge byte-encoding grammar for `BridgeMessageV1`. `Hegemon/Bridge/GenerateVectors.lean` emits Lean-derived bridge encoding and replay examples, and `bash ../../scripts/check_formal_core.sh` compares them against production Rust helpers.
- `Hegemon.Shielded.stage_rejects_zero`, `Hegemon.Shielded.import_rejects_zero`, `Hegemon.Shielded.stage_prevents_duplicate_pending`, `Hegemon.Shielded.import_prevents_reimport`, and `Hegemon.Shielded.import_prevents_restaging` prove the native nullifier anti-double-spend state machine: zero nullifiers are rejected, a staged nullifier cannot be staged twice, and an imported nullifier cannot be imported or staged again.
- `Hegemon/Shielded/GenerateVectors.lean` emits Lean-derived nullifier stage/import examples, and `bash ../../scripts/check_formal_core.sh` compares them against production `protocol-shielded-pool` helpers.

This is real Lean theorem and conformance-vector evidence, but it is deliberately narrow. It does not prove BLAKE3 replay-key derivation, bridge light-client validity, external-chain covenant behavior, full transaction balance conservation, AIR/proof-system soundness, or full native-node equivalence.
