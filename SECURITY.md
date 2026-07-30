# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities to: support@pauli.group

Do NOT open public issues for security vulnerabilities.

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Block Validity Architecture

Block validity is enforced via **independent transaction proofs plus deterministic
consensus replay**:

1. **Transaction proofs**: Each shielded transfer carries one canonical
   V4/Gamma SmallWood proof. Import verifies every proof independently in block
   order.
2. **Block commitments**: The header binds the ordered action body, state roots,
   supply transition, and DA fields. Consensus recomputes those values while
   replaying the block.
3. **DA sampling**: Each node samples erasure-coded chunks using per-node
   randomness that is not predictable by the block producer.

The old commitment-proof and recursive/aggregate authoring backends are not
executable. Historical recursive artifacts retain bounded, canonical
verification solely so existing chain data remains replayable.

## Known Security Limitations

### Deterministic State Replay

- **State transition scope**: Note-tree updates, nullifier uniqueness, supply,
  and block-body commitments are deterministic consensus computations outside
  each transaction proof. The formal supply chain binds accepted transaction
  relations to the ordered block transition, while arbitrary compiled
  native-node refinement remains an explicit assumption.
- **Coinbase-only blocks**: Blocks with no shielded transactions are validated
  directly by the ordinary consensus and supply rules.

### Historical Recursive Proofs

Fresh blocks contain ordered independent V4/Gamma transaction proofs and no
recursive, accumulated, receipt-root, or aggregate authoring artifact. The
historical `recursive_block_v2` decoder/verifier remains for replay only.
Plonky3 authoring crates, source modules, workspace members, and locked
dependencies have been removed. `scripts/check_native_runtime_dependencies.sh`
also fails if a Plonky3 package is reintroduced into a shipped binary graph.

### PQ Security Margins

- Note encryption and PQ transport handshake use ML-KEM-1024 (NIST Level 5) with 32-byte shared secrets.
- Commitments, nullifiers, and Merkle roots use 48-byte (384-bit) digests, yielding ~128-bit post-quantum collision security under generic BHT attacks.
- Local production proving and native action submission use the SmallWood
  V4/Gamma no-grinding profile. It fixes `rho = 5`, five PIOP openings,
  `beta = 7`, a `2^20` DECS domain, 20 distinct DECS openings, and `eta = 33`.
  The production profile guard derives the exact statement geometry and
  rejects any profile below the strict 260-bit interactive floor. V2/Beta and
  V3/Beta verification remain executable only for historical replay.

### Soundness Accounting (Engineering Estimate)

For this repository we track soundness as the minimum of (a) hash-based binding security for Merkle commitments and the Fiat-Shamir transcript and (b) the SmallWood PCS/PIOP/DECS soundness terms for the exact shipped statement geometry.

Hash binding (PQ): for a sponge with capacity `c` bits, generic quantum collision search costs `O(2^{c/3})`, so the engineering security level is approximately `c/3` bits. With 6 Goldilocks field elements of capacity, `c ≈ 6 × 64 = 384` bits, giving ~128-bit post-quantum collision resistance.

SmallWood soundness (current modeled chain): the exact V4/Gamma integer
calculation yields an interactive aggregate floor of approximately `262.718`
bits. The final finite-QROM theorem charges its explicit query-dependent loss
instead of relabeling that interactive number as deployed PQ security.
`ensure_production_smallwood_soundness_floor` derives the four SmallWood terms
from the exact production statement and fails closed below the configured
floor.

The Lean cryptography package proves the exact finite-QROM extraction statement
for the modeled oracle game and carries the accepted proof through the
transaction and block-supply relations. The remaining security boundary is
explicit: deployed domain-separated SHA-512 must instantiate that modeled QRO,
SHA-512 and Poseidon2 must provide the required hardness in their exact
domains, and the checked parser/verifier refinement must match the compiled
Rust execution and machine environment. This is strong internal evidence, not
an independent cryptographic review or permission to claim a NIST level from
the interactive floor alone.

### References (Starting Point)

- Quantum collision finding (collision problem): https://arxiv.org/abs/quant-ph/9705002
- Fiat–Shamir in the quantum random oracle model (QROM): https://eprint.iacr.org/2014/587
- Post-quantum security of Fiat–Shamir: https://eprint.iacr.org/2017/398
- SmallWood transparent arguments for small circuits: https://eprint.iacr.org/2025/1085
- Tip5 (Triton/Neptune) sponge capacity and PQ collision discussion: https://eprint.iacr.org/2023/107.pdf
- RPO (Miden) security levels and 256-bit vs 384-bit capacity variants: https://eprint.iacr.org/2022/1577.pdf
- Poseidon2 design and security discussion: https://eprint.iacr.org/2023/323.pdf
- STARK soundness overview and common 96-bit classical target discussion (blog-level): https://www.starknet.io/blog/safe-and-sound-a-deep-dive-into-stark-security/
