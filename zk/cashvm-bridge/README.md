# Hegemon CashVM Bridge Experiment

This crate models the Bitcoin Cash CashVM-facing objects needed for a Hegemon bridge landing area. It does not implement a production BCH covenant or a full CashVM interpreter.

The experiment keeps the Hegemon source statement stable and backend-neutral. RISC Zero proves `HegemonLongRangeProofV1` inside a zkVM. CashVM should instead receive a BCH-native STARK/hash proof that authenticates the same Hegemon bridge statement but exposes a SHA-256-friendly public output and carries replay state through a 128-byte CashToken commitment.

Run:

```bash
cargo test -p cashvm-bridge --lib
cargo run -p cashvm-bridge --bin cashvm_bridge_report
```

The size report uses the measured Hegemon bridge objects from `docs/bridge_loopback.md`: a 9951-byte long-range proof input, a 404-byte RISC Zero journal, a 224508-byte succinct RISC Zero envelope, and a 492158-byte composite RISC Zero envelope.

The current model shows the Hegemon long-range proof input fits a one-transaction CashVM standardness model, while raw RISC Zero receipt envelopes require proof-fragment transactions. A BCH production bridge should therefore target a CashVM-native STARK/hash proof object rather than direct RISC Zero receipt verification.
