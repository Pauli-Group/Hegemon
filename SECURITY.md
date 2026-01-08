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

### Recursive Proofs (Removed)

Recursive block proofs are currently disabled and the old recursion path has been removed. Reintroducing recursion requires a Plonky3-native design and new AIRs; no legacy recursion feature flags remain.

### PQ Security Margins

- Commitments, nullifiers, and Merkle roots use 48-byte (384-bit) digests, yielding ~128-bit post-quantum collision security under generic BHT attacks.
- Production FRI parameters use log_blowup = 4 (16x) and num_queries = 43, giving an engineering soundness estimate ≥128 bits (see `circuits/transaction-core/src/p3_config.rs`).
