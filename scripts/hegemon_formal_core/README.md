# Hegemon Formal Core Checker

This standalone Cargo project backs `../check_formal_core.sh`. It is intentionally not a root workspace member so it does not expand the normal Hegemon build or the native backend review package surface.

Run from the repository root:

```bash
bash scripts/check_formal_core.sh
```

The checker validates the formal/security claims ledger, validates the blueprint DAG in `config/formal-security-blueprint.json`, verifies independent bridge message vectors, and checks that the active TLA+ model files are present. The shell wrapper also runs the existing `native-backend-ref` vector verifier for native tx-leaf and receipt-root proof artifacts.

The bridge-vector code must not depend on `protocol-kernel`; it reimplements the small canonical encoding and BLAKE3-XOF-48 derivations so production/reference drift is visible.

The blueprint DAG is a JSON review map for the claims ledger, not a Lean proof file. It rejects missing nodes, dangling edges, self-dependencies, dependency cycles, missing implementation or evidence paths, and production-eligible claims without accepted target review or cheap falsification cases.
