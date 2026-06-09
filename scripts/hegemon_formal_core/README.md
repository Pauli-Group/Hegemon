# Hegemon Formal Core Checker

This standalone Cargo project backs `../check_formal_core.sh`. It is intentionally not a root workspace member so it does not expand the normal Hegemon build or the native backend review package surface.

Run from the repository root:

```bash
bash scripts/check_formal_core.sh
```

The checker validates the formal/security claims ledger, validates the blueprint DAG in `config/formal-security-blueprint.json`, verifies independent bridge message vectors, and checks that the active TLA+ and Lean model files are present. For every `lean_theorem` claim, it also requires at least one non-generator Lean evidence file with a named `theorem` declaration, so a claim cannot pass by pointing only at generated vectors or prose. The shell wrapper also builds the pinned Lean proof kernel through `scripts/check_lean_formal.sh`, checks generated Lean-to-Rust bridge vectors through the `protocol-kernel` test target, checks generated Lean-to-Rust shielded-nullifier vectors through the `protocol-shielded-pool` test target, and runs the existing `native-backend-ref` vector verifier for native tx-leaf and receipt-root proof artifacts.

The independent bridge-vector code must not depend on `protocol-kernel`; it reimplements the small canonical encoding and BLAKE3-XOF-48 derivations so production/reference drift is visible. The separate Lean conformance vector paths intentionally run inside production crate test targets and compare bridge encoding/replay plus shielded nullifier behavior against examples emitted by `formal/lean`.

The blueprint DAG is a JSON review map for the claims ledger. It rejects missing nodes, dangling edges, self-dependencies, dependency cycles, missing implementation or evidence paths, and production-eligible claims without accepted target review or cheap falsification cases. Lean theorem evidence must still build under `formal/lean`; JSON metadata alone is not treated as a proof.
