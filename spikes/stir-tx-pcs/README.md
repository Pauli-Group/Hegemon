# STIR Transaction PCS Spike

Standalone spike for a Hegemon-specific STIR opening-layer experiment.

Run:

```sh
cargo run --manifest-path spikes/stir-tx-pcs/Cargo.toml --release
```

This spike:

- reads the checked-in tx proof baseline from `docs/crypto/tx_proof_profile_sweep.json`
- derives the Hegemon tx degree/rate from code
- runs actual STIR and FRI controls using the public academic STIR prototype
- projects the measured STIR/FRI ratio back onto Hegemon's current opening-proof bytes
- refuses to label conjectural or grinding-assisted candidates as release-supported

This is a PCS spike, not a production prover path.
