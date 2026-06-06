# Hegemon Lean Formal Core

This directory contains the machine-checked Lean 4 layer for Hegemon's production-critical validity rules.

The project is pinned by `lean-toolchain` and builds with:

```bash
bash ../../scripts/check_lean_formal.sh
```

Current proved kernel:

- `Hegemon.Bridge.accept_prevents_duplicate` in `Hegemon/Bridge/Replay.lean` proves that once the executable inbound replay-state transition accepts a replay key and returns a next state, the same key cannot be accepted again from that next state.

This is a real Lean theorem, but it is deliberately narrow. It does not prove BLAKE3 replay-key derivation, bridge light-client validity, external-chain covenant behavior, or Rust implementation equivalence. Those require later Lean kernels plus generated vectors and Rust conformance tests.
