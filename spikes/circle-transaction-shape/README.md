# Circle Transaction Shape Spike

Synthetic `p3-circle` / M31 benchmark for a transaction-shaped proof envelope.

Command:

```sh
cargo run --manifest-path spikes/circle-transaction-shape/Cargo.toml --release
```

What it measures:

- `trace_rows = 8192`
- `trace_width = 146`
- `public_values = 76`
- Circle PCS on M31 with `log_blowup = 1`, `num_queries = 40`

What it does not measure:

- Hegemon's real transaction AIR
- Goldilocks/Poseidon2 transaction semantics
- apples-to-apples PQ soundness against the production transaction prover

Use it only as a backend overhead / shape proxy.
