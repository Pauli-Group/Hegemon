# Threat Model

This document explains the attacker capabilities and design assumptions for each subsystem. Keep it synchronized with `DESIGN.md §0-3` and `METHODS.md §Threat Monitoring` whenever behavior or mitigations change.

## Global assumptions

- **Post-quantum only**: Attackers may possess Shor/Grover-class quantum computers. We therefore forbid ECC/RSA and rely on ML-DSA/SLH-DSA signatures, ML-KEM encryption, 256-bit symmetric primitives, and 48-byte (384-bit) digests for commitments and Merkle roots. Grover/BHT reductions are already accounted for with 384-bit collision targets.
- **Transparent proving**: There is no trusted setup; proving soundness relies solely on collision resistance of the STARK-friendly hashes described in `DESIGN.md §2`. Compromise of a setup ceremony is out-of-scope because none exists.
- **Adaptive adversaries**: Attackers can corrupt miners, mining pools, or wallets after observing traffic. Key rotation, nullifier privacy, and block template integrity must hold even with partial compromise.
- **Proof-of-work fairness**: Hash-rate swings and rented rigs are assumed. Difficulty targeting plus share accounting must resist sudden 51% bursts for at least 10 minutes while alerts propagate to pool maintainers.

## Component-specific threats

### `crypto/`

- **Keygen misuse**: Attackers might attempt to bias RNGs. We mitigate this by deriving deterministic seeds from SHA-256 transcripts and exposing APIs that accept explicit seeds for reproducible tests.
- **Serialization downgrade**: Incorrect key lengths lead to acceptance of weak keys. All APIs perform length checks and return errors that bubble up to consensus/wallet callers.

### `circuits/`

- **Soundness breaks via stale constraints**: Transaction/block circuits must include the latest nullifier/account rules. Circuit README + benchmarking harness describe how to recompile constraints and run proofs.
- **Witness leakage**: Benchmarks never persist witness data to disk; they scrub buffers after proof verification to prevent info leaks during profiling.
- **Proof bypass**: Production verification rejects missing STARK bytes or public inputs; no legacy/fast paths are available in production builds.
- **Encoding malleability**: Commitments/nullifiers are 48-byte encodings of six field limbs; any limb ≥ field modulus is rejected to avoid alternate encodings.

### `network/`

- **Peer impersonation**: PQ transport identities must be derived from secret seeds stored with restrictive permissions (0600) or supplied via secure env overrides; seeds must never be derived from public peer IDs to prevent key prediction.

### `consensus/`

- **Network DoS**: Attackers flood PQ-sized signatures and large STARK proofs. The Go net benchmark evaluates miner and pool throughput budgets with inflated payloads, and `METHODS.md` documents required admission-control thresholds for share telemetry.
- **Forking via outdated PQ params**: Consensus nodes pin ML-DSA and ML-KEM parameter sets and reject blocks signed with unknown variants so malicious pools cannot replay stale templates.
- **Miner impersonation**: Share submissions must be signed with approved miner identities; consensus rejects unbound identities even if the PoW difficulty is valid.

### `wallet/`

- **View-key compromise**: Full viewing keys include a view-derived nullifier key (`view_nf`) for spentness tracking but do not embed `sk_spend`; compromise exposes nullifier tracking but not extrinsic signing keys.
- **Metadata leakage**: Wallet bench stresses note batching to keep `rho` diversifiers unpredictable even under load.
- **Disclosure package leakage**: Payment-proof packages include value, asset id, recipient address, commitment, and anchor. Wallet stores encrypt outgoing disclosure records and CLI verification enforces canonical encodings, genesis-hash checks, and on-chain anchor validation to limit replay and tampering risks.

## Security margins

- **Signatures**: Target ≥ 128-bit PQ security (ML-DSA-65 / SLH-DSA-128f). Keys larger than spec are rejected.
- **KEM**: ML-KEM-768 or higher. Shared secrets truncated to 256 bits of entropy.
- **Hashes**: SHA-256/BLAKE3 externally, Poseidon2 field hash internally (width 12, rate 6, capacity 6, 48-byte outputs).
- **Proving**: FRI parameters are set for ≥128-bit engineering soundness (log_blowup 4, num_queries 43, no grinding).

When implementation shifts any of these values, update this document alongside the relevant design/method sections.
