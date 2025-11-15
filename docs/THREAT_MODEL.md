# Threat Model

This document explains the attacker capabilities and design assumptions for each subsystem. Keep it synchronized with `DESIGN.md §0-3` and `METHODS.md §Threat Monitoring` whenever behavior or mitigations change.

## Global assumptions

- **Post-quantum only**: Attackers may possess Shor/Grover-class quantum computers. We therefore forbid ECC/RSA and rely on ML-DSA/SLH-DSA signatures, ML-KEM encryption, and 256-bit symmetric primitives. Grover effectively halves hash security, so all hashes must be ≥256 bits to retain 128-bit security.
- **Transparent proving**: There is no trusted setup; proving soundness relies solely on collision resistance of the STARK-friendly hashes described in `DESIGN.md §2`. Compromise of a setup ceremony is out-of-scope because none exists.
- **Adaptive adversaries**: Attackers can corrupt validators/wallets after observing traffic. Key rotation and nullifier privacy must hold even with partial compromise.

## Component-specific threats

### `crypto/`

- **Keygen misuse**: Attackers might attempt to bias RNGs. We mitigate this by deriving deterministic seeds from SHA-256 transcripts and exposing APIs that accept explicit seeds for reproducible tests.
- **Serialization downgrade**: Incorrect key lengths lead to acceptance of weak keys. All APIs perform length checks and return errors that bubble up to consensus/wallet callers.

### `circuits/`

- **Soundness breaks via stale constraints**: Transaction/block circuits must include the latest nullifier/account rules. Circuit README + benchmarking harness describe how to recompile constraints and run proofs.
- **Witness leakage**: Benchmarks never persist witness data to disk; they scrub buffers after proof verification to prevent info leaks during profiling.

### `consensus/`

- **Network DoS**: Attackers flood PQ-sized signatures and large STARK proofs. The Go net benchmark evaluates throughput budgets with inflated payloads, and `METHODS.md` documents required admission-control thresholds.
- **Forking via outdated PQ params**: Consensus nodes pin ML-DSA and ML-KEM parameter sets and reject blocks signed with unknown variants.

### `wallet/`

- **View-key compromise**: Wallet CLI derives viewing keys using keyed hashes; benchmarks simulate rotation cadence to ensure operations stay tractable.
- **Metadata leakage**: Wallet bench stresses note batching to keep `rho` diversifiers unpredictable even under load.

## Security margins

- **Signatures**: Target ≥ 128-bit PQ security (ML-DSA-65 / SLH-DSA-128f). Keys larger than spec are rejected.
- **KEM**: ML-KEM-768 or higher. Shared secrets truncated to 256 bits of entropy.
- **Hashes**: SHA-256/BLAKE3 externally, Poseidon-like field hash internally. Minimum output 256 bits.
- **Proving**: FRI queries sized for ≥110-bit classical security; Grover halves to ~55-bit, so recursion layers stack to recover ≥128-bit effective security.

When implementation shifts any of these values, update this document alongside the relevant design/method sections.
