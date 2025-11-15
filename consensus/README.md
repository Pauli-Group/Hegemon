# `consensus/`: Validator Logic and Net Benchmarks

`consensus/` contains the Rust crate that maintains ledger state, block validation, and validator APIs. It also owns the Go benchmarking tools under `bench/` that stress gossip throughput with PQ-sized payloads.

## Quickstart

```bash
cargo test -p consensus
(cd bench && go test ./...)
(cd bench && go run ./cmd/netbench --smoke)
```

The Go bench outputs JSON metrics describing achieved throughput and latency with configurable validator counts (`--validators`) and payload sizes (`--payload-bytes`).

## Doc Sync

- Architecture: `DESIGN.md §3`.
- Operational runbooks: `METHODS.md §Consensus`.
- API cross-reference: `docs/API_REFERENCE.md#consensus`.
- Benchmarks and CI instructions: `docs/CONTRIBUTING.md`.

Update all four whenever block formats, validator APIs, or benchmark parameters change.
