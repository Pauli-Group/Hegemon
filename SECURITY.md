# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: support@pauli.group

Do NOT open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Block Validity Architecture

Block validity is enforced via **commitment proofs + parallel transaction-proof verification**:

1. **Commitment proof**: A small STARK that binds the list of transaction proof hashes (via Poseidon sponge), state roots, nullifier uniqueness (via permutation + adjacency checks), and DA root. Verified at block import.
2. **Transaction proofs**: Each shielded transfer carries a STARK proof verified in parallel at import time.
3. **DA sampling**: Each node samples erasure-coded chunks using per-node randomness (not predictable by the block producer).

State-transition Merkle updates are deterministic and computed by consensus at import time, not inside the SNARK.

## Known Security Limitations

### Commitment Proofs

- **Row budget constraints**: In-circuit Merkle updates exceed the ~2^14 row target (each depth-32 append costs ~10k rows), so state transitions are verified outside the proof. This is sound because state updates are deterministic given valid transactions.
- **Nullifier-free blocks**: Blocks with no shielded transactions (coinbase-only) do not carry a commitment proof; they are validated via standard consensus rules.

### Legacy Recursive Proofs (Feature-Gated)

Recursive block proofs are **no longer the default** and are retained only for dev/test maintenance behind `block-circuit/legacy-recursion` + `consensus/legacy-recursion` feature flags.

Known limitations of the legacy path:

- **OOD width overflow**: Transaction proofs require 364 OOD evaluation columns vs Winterfell's 255 cap, making "prove-the-verifier" recursion infeasible without trace redesign.
- **Unsound gated checks**: The legacy recursion path skipped OOD/DEEP/FRI consistency checks due to width limits; these are explicitly unsound and panic by default.
- **Memory/time**: Recursive block proof generation required 100GB+ RAM and 16+ minutes even in dev-fast mode.

### PQ Security Ceiling

- The system uses 256-bit digests and targets ~85-bit post-quantum collision security (limited by generic 2^(n/3) quantum collision search bounds).
- Transaction proofs use quadratic field extension for ~85-bit PQ soundness.
