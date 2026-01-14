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

- Note encryption uses ML-KEM-1024 (NIST Level 5) with 32-byte shared secrets; PQ transport handshake remains ML-KEM-768 until upgraded.
- Commitments, nullifiers, and Merkle roots use 48-byte (384-bit) digests, yielding ~128-bit post-quantum collision security under generic BHT attacks.
- Production FRI parameters use log_blowup = 4 (16x) and num_queries = 32, giving an engineering soundness estimate of 128 bits under the ethSTARK conjecture (see `circuits/transaction-core/src/p3_config.rs` and `p3_fri::FriParameters::conjectured_soundness_bits`).

### Soundness Accounting (Engineering Estimate)

For this repository we track soundness as the minimum of (a) hash-based binding security (Merkle commitments + Fiat–Shamir transcript), and (b) the statistical IOP soundness from FRI.

Hash binding (PQ): for a sponge with capacity `c` bits, generic quantum collision search costs `O(2^{c/3})`, so the engineering security level is approximately `c/3` bits. With 6 Goldilocks field elements of capacity, `c ≈ 6 × 64 = 384` bits, giving ~128-bit post-quantum collision resistance.

FRI IOP soundness (engineering, current): Plonky3’s `p3-fri` exposes this directly as `FriParameters::conjectured_soundness_bits()` (based on the ethSTARK conjecture). With `log_blowup = 4`, `num_queries = 32`, and `pow_bits = 0`, this is 128 bits.

Therefore, with the current production parameters, the limiting factor is the shared 128-bit target itself: hash binding ≈128-bit PQ and FRI IOP ≈128-bit (engineering estimate).

Formal caveat: this is not a formal post-quantum proof in the quantum random-oracle model; it is an engineering-level accounting. A dedicated PQ analysis is required before making stronger external claims.

### References (Starting Point)

- Quantum collision finding (collision problem): https://arxiv.org/abs/quant-ph/9705002
- Fiat–Shamir in the quantum random oracle model (QROM): https://eprint.iacr.org/2014/587
- Post-quantum security of Fiat–Shamir: https://eprint.iacr.org/2017/398
- STARK construction + ALI context (includes FRI/IOP composition): https://eprint.iacr.org/2018/046
- DEEP-FRI soundness amplification: https://eprint.iacr.org/2019/336
- ethSTARK conjectured FRI soundness accounting (used by `p3-fri`): https://eprint.iacr.org/2021/582
- Tip5 (Triton/Neptune) sponge capacity and PQ collision discussion: https://eprint.iacr.org/2023/107.pdf
- RPO (Miden) security levels and 256-bit vs 384-bit capacity variants: https://eprint.iacr.org/2022/1577.pdf
- Poseidon2 design and security discussion: https://eprint.iacr.org/2023/323.pdf
- STARK soundness overview and common 96-bit classical target discussion (blog-level): https://www.starknet.io/blog/safe-and-sound-a-deep-dive-into-stark-security/
