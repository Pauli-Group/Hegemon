# `consensus/`: Miner Coordination and PoW Net Benchmarks

`consensus/` contains the Rust crate that maintains ledger state, block validation, and miner-facing APIs. It also owns the Go benchmarking tools under `bench/` that stress gossip throughput with PQ-sized payloads and simulate proof-of-work miner traffic.

## Quickstart

```bash
cargo test -p consensus
(cd bench && go test ./...)
(cd bench && go run ./cmd/netbench --smoke)
```

The Go bench outputs JSON metrics describing achieved throughput and latency with configurable miner counts (`--miners`), payload sizes (`--payload-bytes`), and PQ signature assumptions (`--pq-signature-bytes`). Use these knobs to tune miner payload composition before rolling changes into production pools.

## Doc Sync

- Architecture: `DESIGN.md §3`.
- Operational runbooks: `METHODS.md §Consensus`.
- API cross-reference: `docs/API_REFERENCE.md#consensus`.
- Benchmarks and CI instructions: `docs/CONTRIBUTING.md`.

Update all four whenever block formats, miner APIs, or benchmark parameters change.
