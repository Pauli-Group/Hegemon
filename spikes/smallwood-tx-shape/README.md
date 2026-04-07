# SmallWood Transaction Shape Spike

Standalone spike for the Hegemon-specific question:

Should a real SmallWood prototype target the current transaction AIR, or the compact native tx-validity relation?

Run:

```sh
cargo run --manifest-path spikes/smallwood-tx-shape/Cargo.toml --release
```

This spike does not prove or verify anything. It derives the relevant witness surfaces from code, compares them to the SmallWood witness regime discussed in the paper, and emits a JSON report with a concrete fit verdict.
